package store

import "errors"

// Field is an encrypted column, named by a stable logical name (ADR-0013).
// The name, never the physical table or column, is bound into a sealed
// value's associated data, so a migration may rename a table or a column and
// every value still opens. Only the fields below exist. A field's name is
// part of the file format: it is never changed, reused, or removed, and a
// test pins every one.
type Field struct{ name string }

// String returns the field's logical name.
func (f Field) String() string { return f.name }

// The encrypted columns of ADR-0011 §3. A value is sealed with the integer
// primary key of the row that holds it. Each field is a function, not a
// variable, so no code can reassign one field to another; a test keeps it
// that way.
func FieldTenantDisplayName() Field     { return Field{"tenant.display_name"} }
func FieldScanManifest() Field          { return Field{"scan.manifest"} }
func FieldScopeAccount() Field          { return Field{"scope.account"} }
func FieldScopeRegion() Field           { return Field{"scope.region"} }
func FieldEvidenceValue() Field         { return Field{"evidence.redacted_value"} }
func FieldEntityNativeID() Field        { return Field{"entity.native_id"} }
func FieldEntityName() Field            { return Field{"entity.name"} }
func FieldEntityTags() Field            { return Field{"entity.tags"} }
func FieldEntityAttributes() Field      { return Field{"entity.attributes"} }
func FieldEntitySnapshotContent() Field { return Field{"entity_snapshot.content"} }
func FieldPermissionCondition() Field   { return Field{"permission.condition"} }
func FieldExposureTrace() Field         { return Field{"exposure.trace"} }
func FieldClassificationLabel() Field   { return Field{"classification.label"} }
func FieldClassificationMethod() Field  { return Field{"classification.method"} }
func FieldClassificationSample() Field  { return Field{"classification.approved_sample"} }
func FieldOverrideActor() Field         { return Field{"criticality_override.actor"} }
func FieldOverrideReason() Field        { return Field{"criticality_override.reason"} }
func FieldReceiptPriorState() Field     { return Field{"remediation_receipt.prior_state"} }
func FieldReceiptRefusal() Field        { return Field{"remediation_receipt.refusal"} }
func FieldFindingDetail() Field         { return Field{"finding.detail"} }
func FieldAttackPathSteps() Field       { return Field{"attack_path.steps"} }
func FieldCutSetChangeSet() Field       { return Field{"cut_set.change_set"} }
func FieldPlanActions() Field           { return Field{"remediation_plan.actions"} }
func FieldPlanPreconditions() Field     { return Field{"remediation_plan.preconditions"} }
func FieldPlanApprovals() Field         { return Field{"remediation_plan.approvals"} }
func FieldPlanRollback() Field          { return Field{"remediation_plan.rollback"} }

// FieldEdgeConditions is also used in edge_snapshots, sealed with the edge's ID.
func FieldEdgeConditions() Field { return Field{"edge.conditions"} }

var (
	errNoField = errors.New("store: a sealed value needs a field")
	errNoRow   = errors.New("store: a sealed value needs its row's key, which is positive")
)

// sealedFields is every field, in the order of the schema.
var sealedFields = []Field{
	FieldTenantDisplayName(), FieldScanManifest(), FieldScopeAccount(), FieldScopeRegion(),
	FieldEvidenceValue(), FieldEntityNativeID(), FieldEntityName(), FieldEntityTags(), FieldEntityAttributes(),
	FieldEntitySnapshotContent(), FieldEdgeConditions(), FieldPermissionCondition(),
	FieldExposureTrace(), FieldClassificationLabel(), FieldClassificationMethod(),
	FieldClassificationSample(), FieldFindingDetail(), FieldAttackPathSteps(),
	FieldCutSetChangeSet(), FieldPlanActions(), FieldPlanPreconditions(),
	FieldPlanApprovals(), FieldPlanRollback(),
	// The list only grows at the end (ADR-0013): new fields are appended.
	FieldOverrideActor(), FieldOverrideReason(),
	FieldReceiptPriorState(), FieldReceiptRefusal(),
}

// hashPurpose names what a keyed hash is of. Every hash of customer content
// is an HMAC under the tenant's keyed-hash key (ADR-0011 §3), separated by
// purpose. Like a field's name, a purpose is never renamed.
type hashPurpose string

const (
	hashScanManifest          hashPurpose = "scan.manifest"
	hashEvidenceValue         hashPurpose = "evidence.value"
	hashEntityContent         hashPurpose = "entity.content"
	hashEdgeContent           hashPurpose = "edge.content"
	hashClassification        hashPurpose = "classification.identity"
	hashClassificationContent hashPurpose = "classification.content"
	hashPermissionID          hashPurpose = "permission.identity"
	hashPermissionContent     hashPurpose = "permission.content"
	hashExposureID            hashPurpose = "exposure.identity"
	hashExposureContent       hashPurpose = "exposure.content"
)

// hashPurposes is every purpose in use.
var hashPurposes = []hashPurpose{
	hashScanManifest, hashEvidenceValue, hashEntityContent, hashEdgeContent,
	hashClassification, hashClassificationContent,
	hashPermissionID, hashPermissionContent, hashExposureID, hashExposureContent,
}
