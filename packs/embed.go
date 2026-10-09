// Package packs embeds the built-in detection packs and their trust root into the binary.
//
// Built-in packs are part of the release-signed artifact (ADR-0009). In addition, the pack
// engine verifies each built-in pack against a first-party pack-signing key
// (ADR-0021 section 2): AllowedSigners returns the embedded trust root, and when it names a
// key, pack.LoadBuiltinAll requires every built-in pack to carry a valid signature in the
// ittcsecscan-pack namespace (fail closed). The trust root now names the pack key and each
// embedded pack ships a committed manifest.json.sig, so built-in packs load fail-closed under
// that key; TestEmbeddedPacksAreSignedAndVerify enforces that every embedded pack is signed
// and verifies. The out-of-band signature path (internal/rules/pack.Load) is always the trust
// mechanism for external packs.
package packs

import "embed"

// FS holds every built-in detection pack directory. Each embedded pack carries a committed
// manifest.json.sig that verifies under the key in keys/allowed_signers.
//
//go:embed all:ai-guard all:core-p0 all:identity-hygiene
var FS embed.FS

// allowedSigners is the built-in pack trust root, in OpenSSH allowed_signers format
// (ittcsecscan-pack namespace).
//
//go:embed keys/allowed_signers
var allowedSigners []byte

// AllowedSigners returns the embedded pack trust root bytes, for pack.TrustedBuiltinKeys.
// It is the source of the keys that pack.LoadBuiltinAll verifies built-in packs against.
func AllowedSigners() []byte { return allowedSigners }

// complianceMapping is the ITTCsecProof compliance-mapping content (ADR-0034): first-party
// data keyed by rule id, carried in packs/ and part of the release-signed artifact
// (ADR-0009). It is not a detection pack (it carries no rules and produces no finding), so
// it is not loaded or verified by the detection-pack engine; its integrity rides the
// binary's release signature, as built-in content does. It is embedded separately from FS
// so the detection-pack loader never sees it.
//
//go:embed compliance/mappings.json
var complianceMapping []byte

// ComplianceMapping returns the embedded ITTCsecProof mapping content, for
// compliance.Load. The returned bytes are the committed, release-signed mapping.
func ComplianceMapping() []byte { return complianceMapping }
