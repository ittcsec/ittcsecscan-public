package collect

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const lambdaCollectorID = "collector:aws.lambda.functions"

const (
	svcLambdaFunctions = "lambda.functions"
	svcLambdaAccess    = "lambda.functionAccess"
	lambdaAPIVersion   = "2015-03-31"
)

// lambdaAPI is the read-only Lambda surface the collector uses: list functions,
// list each function's URL configs, and read each function's resource policy (Lambda
// service authorization reference, verified 2026-10-04). ListFunctions returns the
// function configuration including environment variable values, which this collector
// strips before evidence (never a secret value in evidence); the other two reads
// return a URL/auth type and a resource policy, no secret value.
type lambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListFunctionUrlConfigs(context.Context, *lambda.ListFunctionUrlConfigsInput, ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error)
	GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// LambdaCollector reads the account's Lambda functions in each region, their
// function URLs, and their resource (invoke) policies. A function URL with AuthType
// NONE is anonymously invokable over the internet, and a resource policy that allows
// a wildcard principal is open to cross-account or public invocation; both are
// exposure surfaces the network collector does not see. The function's execution
// role is emitted as an assumes edge so a later engine can judge what an invoker
// reaches.
//
// Environment variable VALUES are stripped structurally: evidence and node facts
// carry only the variable names, never the values (a Lambda env var is a common
// place secrets are set). The strip is by construction, from a sanitized model, not
// a filter over the raw response.
type LambdaCollector struct {
	account string
	api     lambdaAPI
	budget  *collect.Budget
	regions []string
}

// NewLambdaCollector builds the collector with a read-only Lambda client from the
// adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewLambdaCollector(account string, cfg awssdk.Config, budget *collect.Budget) *LambdaCollector {
	return &LambdaCollector{account: account, api: lambda.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

func newLambdaCollector(account string, api lambdaAPI, regions []string) *LambdaCollector {
	return &LambdaCollector{account: account, api: api, regions: regions}
}

func (c *LambdaCollector) ID() string               { return lambdaCollectorID }
func (c *LambdaCollector) Provider() model.Provider { return model.AWS }

func lambdaRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: lambdaCollectorID}
	}
	return []permissions.Requirement{
		req("lambda:ListFunctions"),
		req("lambda:ListFunctionUrlConfigs"),
		req("lambda:GetPolicy"),
	}
}

func init() {
	for _, r := range lambdaRequirements() {
		permissions.Declare(r)
	}
}

func (c *LambdaCollector) Requirements() []permissions.Requirement { return lambdaRequirements() }

// Collect enumerates functions and their access configuration in every region,
// recording lambda.functions and lambda.functionAccess per region.
func (c *LambdaCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			_ = sink.Complete(c.gap(svcLambdaFunctions, region, collect.Partial, 0, "budget exhausted"))
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, 0, "budget exhausted"))
			continue
		}
		budgetOut, err := c.collectRegion(ctx, sink, region)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, err)
		}
		exhausted = budgetOut
	}
	return errors.Join(errs...)
}

func (c *LambdaCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var fns []lambdatypes.FunctionConfiguration
	in := &lambda.ListFunctionsInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcLambdaFunctions, region, collect.Partial, len(fns), "cancelled"))
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, 0, "cancelled"))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.gap(svcLambdaFunctions, region, collect.Partial, len(fns), "budget exhausted"))
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, 0, "budget exhausted"))
			return true, nil
		}
		out, err := c.api.ListFunctions(ctx, in, lambdaInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.gap(svcLambdaFunctions, region, collect.Partial, len(fns), "cancelled"))
				_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, 0, "cancelled"))
				return false, cerr
			}
			_ = sink.Complete(c.completeness(svcLambdaFunctions, region, len(fns), err))
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Complete, 0, ""))
			if isRegionNotEnabled(err) || isDenied(err) || isThrottle(err) || isTransport(err) {
				return false, nil
			}
			return false, err
		}
		// Evidence is built from a sanitized copy with env var values stripped, never
		// the raw response (which carries the values).
		_ = sink.Evidence(c.evidence("ListFunctions", region, sanitizeFunctions(out.Functions)))
		fns = append(fns, out.Functions...)
		if out.NextMarker == nil || *out.NextMarker == "" {
			_ = sink.Complete(c.gap(svcLambdaFunctions, region, collect.Complete, len(fns), ""))
			break
		}
		in.Marker = out.NextMarker
	}
	return c.functionAccess(ctx, sink, region, fns)
}

// functionAccess reads each function's URL configs and resource policy and emits the
// function node with its access facts and its execution-role assumes edge.
func (c *LambdaCollector) functionAccess(ctx context.Context, sink collect.Sink, region string, fns []lambdatypes.FunctionConfiguration) (bool, error) {
	checked := 0
	reason := ""
	for i, fn := range fns {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, checked, "cancelled"))
			return false, err
		}
		// Two calls per function (URL configs, policy): require budget for both.
		if !c.budget.Spend() {
			for _, rest := range fns[i:] {
				c.emit(sink, region, rest, accessFacts{urlAuth: "unknown", policy: "unknown"})
			}
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, checked, "budget exhausted"))
			return true, nil
		}
		af := accessFacts{}

		urls, uerr := c.api.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{FunctionName: fn.FunctionName}, lambdaInRegion(region))
		if uerr != nil {
			if reason == "" {
				reason = c.callReason(uerr)
			}
			af.urlAuth = "unknown"
		} else {
			_ = sink.Evidence(c.evidence("ListFunctionUrlConfigs", region, urls))
			af.hasURL, af.urlAuth, af.publicURL = summarizeURLs(urls.FunctionUrlConfigs)
		}

		if !c.budget.Spend() {
			af.policy = "unknown"
			c.emit(sink, region, fn, af)
			for _, rest := range fns[i+1:] {
				c.emit(sink, region, rest, accessFacts{urlAuth: "unknown", policy: "unknown"})
			}
			_ = sink.Complete(c.gap(svcLambdaAccess, region, collect.Partial, checked, "budget exhausted"))
			return true, nil
		}
		pol, perr := c.api.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn.FunctionName}, lambdaInRegion(region))
		switch {
		case perr != nil && isNoPolicy(perr):
			af.policy = "none"
		case perr != nil:
			if reason == "" {
				reason = c.callReason(perr)
			}
			af.policy = "unknown"
		default:
			_ = sink.Evidence(c.evidence("GetPolicy", region, pol))
			af.policy, af.policyWildcard = summarizePolicy(deref(pol.Policy))
		}

		if uerr == nil && (perr == nil || isNoPolicy(perr)) {
			checked++
		}
		c.emit(sink, region, fn, af)
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(c.gap(svcLambdaAccess, region, status, checked, reason))
	return false, nil
}

// accessFacts are a function's URL and policy observations, all descriptive.
type accessFacts struct {
	hasURL         bool
	urlAuth        string // NONE | AWS_IAM | mixed | none | unknown
	publicURL      bool   // some URL config has AuthType NONE
	policy         string // open | scoped | none | unknown
	policyWildcard bool   // resource policy allows a wildcard principal
}

func (c *LambdaCollector) emit(sink collect.Sink, region string, fn lambdatypes.FunctionConfiguration, af accessFacts) {
	arn := deref(fn.FunctionArn)
	if arn == "" {
		return
	}
	a := map[string]string{
		"aws_type": "lambda-function",
		"region":   region,
		"owner_id": c.account,
		"runtime":  string(fn.Runtime),
		"handler":  deref(fn.Handler),
	}
	if role := deref(fn.Role); role != "" {
		a["role"] = role
	}
	// Environment variable NAMES only; values are never recorded.
	if names := envVarNames(fn.Environment); len(names) > 0 {
		a["env_var_names"] = strings.Join(names, ",")
		a["env_var_count"] = strconv.Itoa(len(names))
	}
	a["has_function_url"] = strconv.FormatBool(af.hasURL)
	a["url_auth_type"] = af.urlAuth
	a["public_url"] = strconv.FormatBool(af.publicURL)
	a["resource_policy"] = af.policy
	a["policy_principal_wildcard"] = strconv.FormatBool(af.policyWildcard)

	_ = sink.Node(collect.Node{Type: model.NodeCompute, NativeID: arn, Name: firstNonEmpty(deref(fn.FunctionName), arn), Attributes: pruneEmpty(a)})
	if role := deref(fn.Role); role != "" {
		_ = sink.Link(collect.Link{SourceNativeID: arn, TargetNativeID: role, Kind: model.EdgeAssumes})
	}
}

// envVarNames returns the sorted names of a function's environment variables, never
// the values.
func envVarNames(env *lambdatypes.EnvironmentResponse) []string {
	if env == nil || len(env.Variables) == 0 {
		return nil
	}
	names := make([]string, 0, len(env.Variables))
	for k := range env.Variables {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// sanitizeFunctions returns a representation of the function configurations with
// environment variable values removed (names kept), for evidence. The strip is
// structural: the sanitized shape never contains a value.
func sanitizeFunctions(fns []lambdatypes.FunctionConfiguration) []map[string]any {
	out := make([]map[string]any, 0, len(fns))
	for _, fn := range fns {
		m := map[string]any{
			"FunctionName": deref(fn.FunctionName),
			"FunctionArn":  deref(fn.FunctionArn),
			"Runtime":      string(fn.Runtime),
			"Handler":      deref(fn.Handler),
			"Role":         deref(fn.Role),
		}
		if names := envVarNames(fn.Environment); len(names) > 0 {
			m["EnvironmentVariableNames"] = names
		}
		out = append(out, m)
	}
	return out
}

// summarizeURLs reports whether the function has any URL, the auth type across its
// URL configs (NONE, AWS_IAM, or mixed), and whether any is anonymously invokable
// (AuthType NONE). ListFunctionUrlConfigs is used so an alias URL is not missed.
func summarizeURLs(cfgs []lambdatypes.FunctionUrlConfig) (has bool, auth string, public bool) {
	if len(cfgs) == 0 {
		return false, "none", false
	}
	seen := map[string]bool{}
	for _, u := range cfgs {
		at := string(u.AuthType)
		seen[at] = true
		if u.AuthType == lambdatypes.FunctionUrlAuthTypeNone {
			public = true
		}
	}
	if len(seen) == 1 {
		for at := range seen {
			auth = at
		}
	} else {
		auth = "mixed"
	}
	return true, auth, public
}

// summarizePolicy classifies a Lambda resource policy: open if an Allow statement
// grants a wildcard principal, scoped otherwise. A malformed policy is "unknown".
func summarizePolicy(doc string) (class string, wildcard bool) {
	if doc == "" {
		return "none", false
	}
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &raw) != nil || len(raw.Statement) == 0 {
		return "unknown", false
	}
	var stmts []lambdaPolicyStatement
	if json.Unmarshal(raw.Statement, &stmts) != nil {
		var one lambdaPolicyStatement
		if json.Unmarshal(raw.Statement, &one) != nil {
			return "unknown", false
		}
		stmts = []lambdaPolicyStatement{one}
	}
	for _, s := range stmts {
		if strings.EqualFold(s.Effect, "Allow") && lambdaPrincipalWildcard(s.Principal) {
			wildcard = true
		}
	}
	if wildcard {
		return "open", true
	}
	return "scoped", false
}

// lambdaPolicyStatement is a resource-policy statement with the Principal the
// function invoke policy uses. It is local to this collector so it does not depend
// on another collector's policy types.
type lambdaPolicyStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
}

// lambdaPrincipalWildcard reports whether a policy Principal is the wildcard "*" or
// {"AWS":"*"} (optionally a list containing "*").
func lambdaPrincipalWildcard(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for _, v := range obj {
			if hasExact(stringOrSlice(v), "*") {
				return true
			}
		}
	}
	return false
}

// isNoPolicy reports the Lambda GetPolicy "function has no resource policy" error,
// which is not a failure: the function simply has no policy.
func isNoPolicy(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == "ResourceNotFoundException"
}

func (c *LambdaCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *LambdaCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "lambda", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: lambdaAPIVersion, Collector: lambdaCollectorID},
	}
}

func (c *LambdaCollector) gap(service, region string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

func (c *LambdaCollector) completeness(service, region string, collected int, err error) collect.Completeness {
	status := collect.Errored
	reason := redact.String(err.Error())
	switch {
	case isRegionNotEnabled(err):
		status = collect.Unsupported
		reason = "region not enabled"
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	case isTransport(err):
		status = collect.Partial
		reason = "unreachable"
	}
	return c.gap(service, region, status, collected, reason)
}

func (c *LambdaCollector) callReason(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	case isTransport(err):
		return "unreachable"
	}
	return redact.String(err.Error())
}

// lambdaInRegion targets one region for a Lambda call.
func lambdaInRegion(region string) func(*lambda.Options) {
	return func(o *lambda.Options) { o.Region = region }
}
