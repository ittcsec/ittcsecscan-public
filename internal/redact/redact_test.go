package redact

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Test credentials are assembled at run time so that secret scanners do not
// flag this file, and so that no string here is a real credential.
var (
	awsKeyID   = "AKIA" + "Z7CANARY0000TEST"
	awsTmpID   = "ASIA" + "Z7CANARY0000TEST"
	ghToken    = "ghp_" + strings.Repeat("c4n4ry", 6)
	glToken    = "glpat-" + strings.Repeat("c4n4ry", 4)
	googleKey  = "AIza" + strings.Repeat("C", 35)
	slackTok   = "xoxb-" + "1234567890-canary"
	jwtToken   = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJjYW5hcnkifQ" + ".c2lnbmF0dXJl"
	envSecret  = "canary-" + strings.Repeat("s", 33)
	gcpAccess  = "ya29." + strings.Repeat("C", 40)
	gcpRefresh = "1//" + strings.Repeat("R", 40)
	sigv4Hex   = strings.Repeat("fe5f80f7", 8)
	pemBlock   = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA " + "PRIVATE KEY-----"
)

func TestStringRedactsKnownSecrets(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		secret string
	}{
		{"aws key id", "using key " + awsKeyID + " now", "using key [REDACTED] now", awsKeyID},
		{"aws temporary key id", awsTmpID, "[REDACTED]", awsTmpID},
		{"aws key with trailing material", awsKeyID + "EXTRA", "[REDACTED]", "EXTRA"},
		{"github token", "token " + ghToken, "token [REDACTED]", ghToken},
		{"gitlab token", "token " + glToken, "token [REDACTED]", glToken},
		{"google api key", "k=" + googleKey, "k=[REDACTED]", googleKey},
		{"slack token", slackTok, "[REDACTED]", slackTok},
		{"jwt", "id " + jwtToken + " end", "id [REDACTED] end", "c2lnbmF0dXJl"},
		{"pem block", "before\n" + pemBlock + "\nafter", "before\n[REDACTED]\nafter", "MIIBOgIBAAJBAKj34"},
		{"pem block without end marker", "x " + strings.Split(pemBlock, "-----END")[0], "x [REDACTED]", "MIIBOgIBAAJBAKj34"},
		{"url userinfo", "fetch https://alice:s3cr3tpw@example.com/p", "fetch https://[REDACTED]@example.com/p", "s3cr3tpw"},
		{"bearer header", "Authorization: Bearer abcdefghijklmnop0123", "Authorization: Bearer [REDACTED]", "abcdefghijklmnop0123"},
		{"ssws header", "Authorization: SSWS 00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "Authorization: SSWS [REDACTED]", "00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"},
		{"basic header", "authorization: basic dXNlcjpwYXNzd29yZDEyMw==", "authorization: basic [REDACTED]", "dXNlcjpwYXNzd29yZDEyMw"},
		{"password assignment", "password=hunter2x", "password=[REDACTED]", "hunter2x"},
		{"secret with colon", "client_secret: abc123", "client_secret: [REDACTED]", "abc123"},
		{"json field", `{"client_secret": "abc\"def", "region": "eu"}`, `{"client_secret": [REDACTED], "region": "eu"}`, "def"},
		{"single quoted", `api_key='k3y'`, `api_key=[REDACTED]`, "k3y"},
		{"env style", "AWS_SECRET_ACCESS_KEY=" + envSecret, "AWS_SECRET_ACCESS_KEY=[REDACTED]", envSecret},
		{"azure sas query", "https://a.blob.core.windows.net/c?sv=2024-01-01&sig=abc%2Bdef&se=2026", "https://a.blob.core.windows.net/c?sv=2024-01-01&sig=[REDACTED]&se=2026", "abc%2Bdef"},
		{"azure connection string", "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=abc123==;EndpointSuffix=core.windows.net", "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=[REDACTED];EndpointSuffix=core.windows.net", "abc123=="},
		{"pwd parameter", "Server=db;Uid=app;Pwd=pa55;", "Server=db;Uid=app;Pwd=[REDACTED];", "pa55"},
		{"gcp access token", "token " + gcpAccess + " ok", "token [REDACTED] ok", gcpAccess},
		{"gcp refresh token", "refresh=" + gcpRefresh, "refresh=[REDACTED]", gcpRefresh},
		{"aws sigv4 signature", "Signature=" + sigv4Hex, "Signature=[REDACTED]", sigv4Hex},
		{"aws sigv4 header", "Authorization: AWS4-HMAC-SHA256 Credential=" + awsKeyID + "/20260917/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=" + sigv4Hex, "Authorization: AWS4-HMAC-SHA256 Credential=[REDACTED], SignedHeaders=host, Signature=[REDACTED]", sigv4Hex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.in)
			if got != tt.want {
				t.Errorf("String(%q)\n got  %q\n want %q", tt.in, got, tt.want)
			}
			if strings.Contains(got, tt.secret) {
				t.Errorf("output still contains secret material %q: %q", tt.secret, got)
			}
			if again := String(got); again != got {
				t.Errorf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestStringLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"scan completed in 3.2s",
		"region=eu-west-1 account=123456789012",
		"Basic auth disabled",
		"tokenizer ready",
		"design=blue",
		"ssh://git@github.com/org/repo",
		"arn:aws:iam::123456789012:role/Scanner",
		"signature verification: ok",
		"1//2 of the batch complete",
		"ya29 release notes published",
	} {
		if got := String(in); got != in {
			t.Errorf("String(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestKey(t *testing.T) {
	sensitive := []string{
		"password", "PASSWORD", "db_passwd", "passphrase",
		"aws_secret_access_key", "AWS_ACCESS_KEY_ID", "client-secret", "clientSecret",
		"x-api-key", "apiKey", "token", "SessionToken", "id_token",
		"Authorization", "cookie", "session_id", "private_key", "privateKey",
		"account_key", "SharedAccessKey", "connection_string", "credentials",
		"signature", "client_assertion", "sig", "pwd", "key", "auth", "sas",
	}
	for _, k := range sensitive {
		if !Key(k) {
			t.Errorf("Key(%q) = false, want true", k)
		}
	}
	benign := []string{
		"", "region", "account_id", "tenant", "path", "keyring", "monkey",
		"author", "provider", "resource_type", "count",
	}
	for _, k := range benign {
		if Key(k) {
			t.Errorf("Key(%q) = true, want false", k)
		}
	}
}

func TestSecretNeverRenders(t *testing.T) {
	s := NewSecret("hunter2-canary")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		got := fmt.Sprintf(verb, s)
		if verb == "%T" {
			if strings.Contains(got, "hunter2") {
				t.Errorf("%s leaked: %q", verb, got)
			}
			continue
		}
		if got != Placeholder {
			t.Errorf("fmt %s = %q, want %q", verb, got, Placeholder)
		}
	}
	type wrapper struct {
		Name   string
		Secret Secret
	}
	w := wrapper{Name: "n", Secret: s}
	for _, got := range []string{fmt.Sprintf("%v", w), fmt.Sprintf("%+v", w), fmt.Sprintf("%#v", w)} {
		if strings.Contains(got, "hunter2") {
			t.Errorf("struct formatting leaked secret: %q", got)
		}
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") || !strings.Contains(string(b), Placeholder) {
		t.Errorf("json leaked or missing placeholder: %s", b)
	}
	text, err := s.MarshalText()
	if err != nil || string(text) != Placeholder {
		t.Errorf("MarshalText = %q, %v", text, err)
	}
	if s.LogValue().String() != Placeholder {
		t.Errorf("LogValue = %q", s.LogValue().String())
	}
	if s.Reveal() != "hunter2-canary" {
		t.Errorf("Reveal returned wrong value")
	}
	if s.IsZero() || !NewSecret("").IsZero() {
		t.Errorf("IsZero wrong")
	}
}

func FuzzString(f *testing.F) {
	f.Add("", "")
	f.Add("password=", ";")
	f.Add(`{"token": "`, `"}`)
	f.Add("https://u:", "@host/")
	f.Add("Authorization: Bearer ", "")
	f.Add("eyJabcd.eyJ", ".sig")
	f.Add("-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----")
	f.Add("AIza", "ghp_")
	f.Add("ya29.", "")
	f.Add("Signature=", "")
	f.Add("1//", "")
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		// Idempotence on arbitrary input.
		once := String(prefix + suffix)
		if twice := String(once); twice != once {
			t.Fatalf("not idempotent:\n in    %q\n once  %q\n twice %q", prefix+suffix, once, twice)
		}
		// Known credentials of each shape survive no surrounding context.
		for _, cred := range []string{awsKeyID, gcpAccess, gcpRefresh} {
			out := String(prefix + cred + suffix)
			if strings.Contains(out, cred) {
				t.Fatalf("credential %q leaked through context %q ... %q: %q", cred, prefix, suffix, out)
			}
		}
	})
}
