package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// lambdaRegion reads the region an optFn targets.
func lambdaRegion(o []func(*lambda.Options)) string {
	opt := &lambda.Options{}
	for _, f := range o {
		f(opt)
	}
	return opt.Region
}

// stubLambda is an offline lambdaAPI keyed by region and function name.
type stubLambda struct {
	byRegion map[string][]lambdatypes.FunctionConfiguration
	urls     map[string][]lambdatypes.FunctionUrlConfig // functionName -> url configs
	policies map[string]string                          // functionName -> resource policy JSON
	errs     map[string]error                           // "ListFunctions@region", "url@name", "policy@name"
}

func (s *stubLambda) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, o ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	r := lambdaRegion(o)
	if err := s.errs["ListFunctions@"+r]; err != nil {
		return nil, err
	}
	return &lambda.ListFunctionsOutput{Functions: s.byRegion[r]}, nil
}

func (s *stubLambda) ListFunctionUrlConfigs(_ context.Context, in *lambda.ListFunctionUrlConfigsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error) {
	name := deref(in.FunctionName)
	if err := s.errs["url@"+name]; err != nil {
		return nil, err
	}
	return &lambda.ListFunctionUrlConfigsOutput{FunctionUrlConfigs: s.urls[name]}, nil
}

func (s *stubLambda) GetPolicy(_ context.Context, in *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	name := deref(in.FunctionName)
	if err := s.errs["policy@"+name]; err != nil {
		return nil, err
	}
	pol, ok := s.policies[name]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	return &lambda.GetPolicyOutput{Policy: ptr(pol)}, nil
}

func runLambda(t *testing.T, api lambdaAPI, regions ...string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newLambdaCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func fn(name string, env map[string]string) lambdatypes.FunctionConfiguration {
	c := lambdatypes.FunctionConfiguration{
		FunctionName: ptr(name),
		FunctionArn:  ptr("arn:aws:lambda:us-east-1:" + acctID + ":function:" + name),
		Runtime:      lambdatypes.RuntimeNodejs20x,
		Handler:      ptr("index.handler"),
		Role:         ptr("arn:aws:iam::" + acctID + ":role/" + name + "-role"),
	}
	if env != nil {
		c.Environment = &lambdatypes.EnvironmentResponse{Variables: env}
	}
	return c
}

func computeNode(s collect.Scan, nameSuffix string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeCompute && strings.HasSuffix(n.NativeID, nameSuffix) {
			return n, true
		}
	}
	return collect.Node{}, false
}

const openInvokePolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"public","Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Resource":"*"}]}`

// TestLambdaPublicUrlAndPolicy proves a function with a NONE-auth URL and a
// wildcard-principal resource policy is recorded public_url=true, url_auth_type=NONE,
// resource_policy=open, and that the execution-role assumes edge is emitted.
func TestLambdaPublicUrlAndPolicy(t *testing.T) {
	s := runLambda(t, &stubLambda{
		byRegion: map[string][]lambdatypes.FunctionConfiguration{"us-east-1": {fn("pub", map[string]string{"API_KEY": "s3cr3t-value"})}},
		urls:     map[string][]lambdatypes.FunctionUrlConfig{"pub": {{AuthType: lambdatypes.FunctionUrlAuthTypeNone, FunctionUrl: ptr("https://x.lambda-url.us-east-1.on.aws/")}}},
		policies: map[string]string{"pub": openInvokePolicy},
	}, "us-east-1")

	if c := lambdaCompletenessAt(s, "lambda.functions", "us-east-1"); c.Status != collect.Complete || c.Collected != 1 {
		t.Fatalf("lambda.functions = %+v, want complete/1", c)
	}
	n, ok := computeNode(s, "function:pub")
	if !ok {
		t.Fatal("function node not emitted")
	}
	for k, want := range map[string]string{
		"public_url": "true", "url_auth_type": "NONE", "has_function_url": "true",
		"resource_policy": "open", "policy_principal_wildcard": "true",
		"env_var_names": "API_KEY",
	} {
		if n.Attributes[k] != want {
			t.Errorf("fact %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	found := false
	for _, l := range s.Links {
		if l.Kind == model.EdgeAssumes && strings.HasSuffix(l.SourceNativeID, "function:pub") && strings.HasSuffix(l.TargetNativeID, "role/pub-role") {
			found = true
		}
	}
	if !found {
		t.Errorf("no assumes edge from function to its execution role: %+v", s.Links)
	}
}

// TestLambdaEnvValuesNeverInEvidence proves the environment variable VALUES never
// reach evidence (only the names do): the amendment-1 guarantee for Lambda.
func TestLambdaEnvValuesNeverInEvidence(t *testing.T) {
	s := runLambda(t, &stubLambda{
		byRegion: map[string][]lambdatypes.FunctionConfiguration{"us-east-1": {fn("f", map[string]string{"DB_PASSWORD": "hunter2-secret", "REGION": "us-east-1"})}},
	}, "us-east-1")

	for _, e := range s.Envelopes {
		body := string(e.Response)
		for _, secret := range []string{"hunter2-secret", "s3cr3t-value"} {
			if strings.Contains(body, secret) {
				t.Errorf("evidence leaked an env var value %q: %s", secret, e.Operation)
			}
		}
	}
	// The names are still present (as a node fact), so the strip did not lose signal.
	n, ok := computeNode(s, "function:f")
	if !ok || !strings.Contains(n.Attributes["env_var_names"], "DB_PASSWORD") {
		t.Errorf("env var names should be recorded: %+v", n.Attributes)
	}
}

// TestLambdaScopedNoPolicy proves an AWS_IAM URL with no resource policy is
// recorded public_url=false, url_auth_type=AWS_IAM, resource_policy=none.
func TestLambdaScopedNoPolicy(t *testing.T) {
	s := runLambda(t, &stubLambda{
		byRegion: map[string][]lambdatypes.FunctionConfiguration{"us-east-1": {fn("iam", nil)}},
		urls:     map[string][]lambdatypes.FunctionUrlConfig{"iam": {{AuthType: lambdatypes.FunctionUrlAuthTypeAwsIam, FunctionUrl: ptr("https://y.lambda-url.us-east-1.on.aws/")}}},
		// no policy entry -> GetPolicy returns ResourceNotFoundException
	}, "us-east-1")

	n, ok := computeNode(s, "function:iam")
	if !ok {
		t.Fatal("function node not emitted")
	}
	for k, want := range map[string]string{"public_url": "false", "url_auth_type": "AWS_IAM", "resource_policy": "none"} {
		if n.Attributes[k] != want {
			t.Errorf("fact %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
}

// TestLambdaDeniedListIsGap proves a denied ListFunctions is Denied with no nodes,
// and the access pass is an honest Complete/0.
func TestLambdaDeniedListIsGap(t *testing.T) {
	s := runLambda(t, &stubLambda{errs: map[string]error{"ListFunctions@us-east-1": apiErr("AccessDeniedException")}}, "us-east-1")
	if statusOf(s, "lambda.functions") != collect.Denied {
		t.Errorf("lambda.functions = %s, want denied", statusOf(s, "lambda.functions"))
	}
	if c := lambdaCompletenessAt(s, "lambda.functionAccess", "us-east-1"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("lambda.functionAccess = %+v, want complete/0", c)
	}
	if nodesByType(s)[model.NodeCompute] != 0 {
		t.Error("no function nodes should be emitted on a denied list")
	}
}

// TestLambdaUrlFailureIsUnknown proves a function whose URL read failed is
// url_auth_type=unknown and the access pass is Partial with the reason.
func TestLambdaUrlFailureIsUnknown(t *testing.T) {
	s := runLambda(t, &stubLambda{
		byRegion: map[string][]lambdatypes.FunctionConfiguration{"us-east-1": {fn("f", nil)}},
		errs:     map[string]error{"url@f": apiErr("AccessDeniedException")},
	}, "us-east-1")
	n, ok := computeNode(s, "function:f")
	if !ok || n.Attributes["url_auth_type"] != "unknown" {
		t.Errorf("function with failed URL read url_auth_type = %q (ok=%v), want unknown", n.Attributes["url_auth_type"], ok)
	}
	if c := lambdaCompletenessAt(s, "lambda.functionAccess", "us-east-1"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("lambda.functionAccess = %+v, want partial/denied", c)
	}
}

// lambdaCompletenessAt returns the completeness for a (service, region) pair.
func lambdaCompletenessAt(s collect.Scan, service, region string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service && c.Region == region {
			return c
		}
	}
	return collect.Completeness{}
}
