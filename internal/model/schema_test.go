package model_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

func sid(b byte) model.StableID {
	return model.StableID(strings.Repeat(string("0123456789abcdef"[b%16]), 64))
}

// fullDocuments maps each model schema name to a fully populated instance, so
// the schema-validation test proves the Go wire form satisfies its published
// schema (schemas/README.md; the pattern used for the CLI schemas).
func fullDocuments(t *testing.T) map[string]any {
	t.Helper()
	ts := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ev := model.Evidence{
		SchemaVersion: model.SchemaVersion, Collector: "iam", API: "iam:ListRoles",
		ObservedAt: ts, Value: "redacted", Freshness: model.Fresh, Completeness: model.Complete,
	}
	proto := 6
	return map[string]any{
		schema.ModelEntity: model.Entity{
			SchemaVersion: model.SchemaVersion, ID: sid(1), Provider: model.AWS, Type: model.NodeRole,
			NativeID: "arn:aws:iam::111111111111:role/app", Name: "app", Criticality: 3,
			Tags: map[string]string{"env": "prod"}, Attributes: map[string]string{"path": "/"},
			FirstSeen: ts, LastSeen: ts,
		},
		schema.ModelEdge: model.Edge{
			SchemaVersion: model.SchemaVersion, Source: sid(1), Target: sid(2), Kind: model.EdgeCanRead,
			Conditions:    []model.Condition{{Key: "aws:SourceIp", Operator: "IpAddress", Values: []string{"10.0.0.0/8"}}},
			DenyEvaluated: model.Yes, Freshness: model.Fresh, Confidence: 80,
			Evidence: []model.Evidence{ev}, Explanation: []string{"role policy allows s3:GetObject"},
		},
		schema.ModelPermission: model.Permission{
			SchemaVersion: model.SchemaVersion, Principal: sid(1), Resource: sid(2),
			Action: "s3:GetObject", Effect: model.Effect("allow"),
			Condition:     []model.Condition{{Key: "s3:prefix", Operator: "StringLike", Values: []string{"data/*"}}},
			InheritedFrom: sid(3),
		},
		schema.ModelExposure: model.Exposure{
			SchemaVersion: model.SchemaVersion, Entity: sid(1), Zone: model.Zone("internet"),
			Protocol: &proto, Ports: &model.PortRange{From: 443, To: 443},
			AuthRequired: model.No, Effective: model.Yes, Trace: []string{"igw -> sg allows 443"},
		},
		schema.ModelClassification: model.Classification{
			SchemaVersion: model.SchemaVersion, Entity: sid(1), Label: "crown-jewel", Method: "pattern",
			Confidence: 90, ApprovedSample: "s3://bucket/redacted",
		},
		schema.ModelEvidence: ev,
		schema.ModelScanManifest: model.ScanManifest{
			SchemaVersion: model.SchemaVersion, ToolVersion: "0.0.0-dev", StartedAt: ts, CompletedAt: &ts,
			Status: model.ScanCompleted,
			Scopes: []model.Scope{{Provider: model.AWS, Account: "111111111111", Region: "eu-west-1", Requested: 10, Observed: 10, Completeness: model.Complete}},
		},
		schema.ModelFinding: model.Finding{
			SchemaVersion: model.SchemaVersion, Rule: model.RuleRef{RuleID: "S3.1", Version: "1.0.0", PackID: "aws-core"},
			Entity: sid(1), State: model.Fail, Risk: 80, Confidence: 90, FirstSeen: ts,
			Status: model.FindingStatus("open"), Detail: "public bucket",
		},
		schema.ModelAttackPath: model.AttackPath{
			SchemaVersion: model.SchemaVersion, Entry: sid(1), Target: sid(2), Score: 75, Confidence: 80,
			Steps: []model.PathStep{{Node: sid(1), Via: model.EdgeAssumes, Technique: "T1078"}, {Node: sid(2), Via: model.EdgeCanRead}},
		},
		schema.ModelCutSet: model.CutSet{
			SchemaVersion: model.SchemaVersion,
			Changes:       []model.CutChange{{Source: sid(1), Target: sid(2), Kind: model.EdgeTrusts, Description: "remove cross-account trust"}},
			PathsRemoved:  4, RiskReduction: 60, Effort: 2, Disruption: 1,
		},
		schema.ModelRemediationPlan: model.RemediationPlan{
			SchemaVersion: model.SchemaVersion,
			Finding:       model.RuleRef{RuleID: "S3.1", Version: "1", PackID: "core-p0"},
			Entity:        sid(1), Available: true,
			Actions: []model.RemediationAction{{
				Provider: model.AWS, Service: "s3", Summary: "block public access",
				PortalSteps: []string{"open the bucket"}, CLI: []string{"aws s3api put-public-access-block"},
				IaC: "aws_s3_bucket_public_access_block", Privilege: []string{"s3:PutBucketPublicAccessBlock"},
			}},
			Preconditions: []string{"no active sessions"}, RequiredPrivilege: []string{"s3:PutBucketPublicAccessBlock"},
			SideEffects: []string{"public distribution stops"}, Approvals: []string{"owner"},
			Verification: []string{"re-read public access block"}, Reversible: true,
			Rollback: []string{"reattach policy"},
		},
	}
}

// Each canonical document's Go wire form validates against its published JSON
// Schema (ADR-0014; schemas/README.md compatibility policy).
func TestModelDocumentsMatchTheirSchemas(t *testing.T) {
	for name, doc := range fullDocuments(t) {
		if err := schema.ValidateValue(name, doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The document schemas are closed: an unknown field is rejected, so a typo or a
// leaked store field fails validation rather than passing silently.
func TestModelSchemasRejectUnknownFields(t *testing.T) {
	for name, doc := range fullDocuments(t) {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["node_id"] = 42 // a store field must never be accepted
		spoiled, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.ValidateJSON(name, spoiled); err == nil {
			t.Errorf("%s: an unknown field (node_id) was accepted", name)
		}
	}
}

// Every embedded model schema carries a versioned URN $id (schemas/README.md).
func TestModelSchemaNamesAreRegistered(t *testing.T) {
	for _, name := range []string{
		schema.ModelEntity, schema.ModelEdge, schema.ModelPermission, schema.ModelExposure,
		schema.ModelClassification, schema.ModelEvidence, schema.ModelScanManifest,
		schema.ModelFinding, schema.ModelAttackPath, schema.ModelCutSet, schema.ModelRemediationPlan,
	} {
		if err := schema.ValidateValue(name, map[string]any{}); err == nil {
			t.Errorf("%s: an empty object validated; the schema is not enforcing required fields", name)
		}
	}
}
