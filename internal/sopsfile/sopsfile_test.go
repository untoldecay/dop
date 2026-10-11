package sopsfile

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

const sample = `schema_version: v1
n: 42
f: 1.5
b: true
empty: ""
nul: null
list:
  - a
  - 7
  - {k: v, num: 3}
nested:
  deep:
    x: hello
    when: "2026-10-11T09:00:00Z"
  keep_unencrypted: visible
  sub_unencrypted:
    inner: also-visible
admins:
  - name: camille
    age_recipient: age1example
`

func newID(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func asAny(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatalf("yaml: %v\n%s", err, b)
	}
	return v
}

func TestRoundTrip(t *testing.T) {
	id := newID(t)
	enc, err := Encrypt([]byte(sample), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("hello")) || bytes.Contains(enc, []byte("camille")) {
		t.Fatalf("plaintext leaked:\n%s", enc)
	}
	for _, clear := range []string{"keep_unencrypted: visible", "inner: also-visible", `empty: ""`, "nul: null"} {
		if !bytes.Contains(enc, []byte(clear)) {
			t.Errorf("expected %q in clear:\n%s", clear, enc)
		}
	}
	if !IsEncrypted(enc) {
		t.Fatal("IsEncrypted false on output")
	}
	plain, err := Decrypt(enc, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(asAny(t, plain), asAny(t, []byte(sample))) {
		t.Fatalf("round trip differs:\n%s", plain)
	}
}

func TestMultipleRecipients(t *testing.T) {
	a, b := newID(t), newID(t)
	enc, err := Encrypt([]byte(sample), []string{a.Recipient().String(), b.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []age.Identity{a, b} {
		if _, err := Decrypt(enc, id); err != nil {
			t.Fatalf("recipient can't open: %v", err)
		}
	}
	if _, err := Decrypt(enc, newID(t)); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("stranger: want ErrNoMatchingKey, got %v", err)
	}
	// The phrase the TUI matches for "not on the admin list".
	if !strings.Contains(ErrNoMatchingKey.Error(), "no master key was able to decrypt") {
		t.Fatal("ErrNoMatchingKey lost the phrase friendlyDecryptError matches")
	}
}

func TestTamper(t *testing.T) {
	id := newID(t)
	enc, err := Encrypt([]byte("a: one\nb: two\n"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(enc, &doc); err != nil {
		t.Fatal(err)
	}
	// Swap two encrypted values: each is bound to its path → must fail.
	swapped := bytes.Replace(enc, []byte(doc["a"].(string)), []byte("X"), 1)
	swapped = bytes.Replace(swapped, []byte(doc["b"].(string)), []byte(doc["a"].(string)), 1)
	swapped = bytes.Replace(swapped, []byte("X"), []byte(doc["b"].(string)), 1)
	if _, err := Decrypt(swapped, id); err == nil {
		t.Fatal("swapped values decrypted")
	}
	// Remove a key: values still decrypt, but the MAC must catch it.
	dropped := bytes.Replace(enc, []byte("b: "+doc["b"].(string)+"\n"), nil, 1)
	if _, err := Decrypt(dropped, id); err == nil || !strings.Contains(err.Error(), "MAC mismatch") {
		t.Fatalf("dropped key: want MAC mismatch, got %v", err)
	}
}

func TestNotEncrypted(t *testing.T) {
	if _, err := Decrypt([]byte("a: b\n"), newID(t)); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("want ErrNotEncrypted, got %v", err)
	}
	if _, err := Encrypt([]byte("sops: {}\n"), []string{newID(t).Recipient().String()}); err == nil {
		t.Fatal("encrypting a file with a sops key should fail")
	}
}

// --- compatibility with the real sops binary (skipped when absent) ---

func sopsBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops not on PATH")
	}
	return p
}

func runSops(t *testing.T, id *age.X25519Identity, stdin []byte, args ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.yaml")
	if err := os.WriteFile(in, stdin, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sopsBin(t), append(args, "--input-type", "yaml", "--output-type", "yaml", in)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+id.String())
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops %v: %v\n%s", args, err, errb.String())
	}
	return out.Bytes()
}

func TestSopsReadsOurs(t *testing.T) {
	id := newID(t)
	enc, err := Encrypt([]byte(sample), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	plain := runSops(t, id, enc, "--decrypt")
	if !reflect.DeepEqual(asAny(t, plain), asAny(t, []byte(sample))) {
		t.Fatalf("sops decrypt of our file differs:\n%s", plain)
	}
}

func TestWeReadSops(t *testing.T) {
	id := newID(t)
	enc := runSops(t, id, []byte(sample), "--encrypt", "--age", id.Recipient().String())
	plain, err := Decrypt(enc, id)
	if err != nil {
		t.Fatalf("%v\n%s", err, enc)
	}
	want := runSops(t, id, enc, "--decrypt")
	if !reflect.DeepEqual(asAny(t, plain), asAny(t, want)) {
		t.Fatalf("differs from sops:\nours:\n%s\nsops:\n%s", plain, want)
	}
}

// Same layout as sops: re-encrypting sops's own plaintext with the
// same structure gives the same lines apart from ciphertext.
func TestLayoutMatchesSops(t *testing.T) {
	id := newID(t)
	theirs := runSops(t, id, []byte(sample), "--encrypt", "--age", id.Recipient().String())
	ours, err := Encrypt([]byte(sample), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if a, b := shape(theirs), shape(ours); a != b {
		t.Fatalf("layout differs:\nsops:\n%s\nours:\n%s", a, b)
	}
}

// shape blanks out ciphertext, armor bodies and timestamps.
func shape(b []byte) string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.Index(l, "ENC["); i >= 0 {
			l = l[:i] + "ENC[…]"
		}
		trim := strings.TrimSpace(l)
		if trim != "" && !strings.HasPrefix(trim, "-----") && !strings.Contains(trim, ":") && !strings.HasPrefix(trim, "-") {
			l = "<armor>"
		}
		if strings.Contains(l, "lastmodified:") || strings.Contains(l, "recipient:") || strings.Contains(l, "version:") {
			l = strings.SplitN(l, ":", 2)[0] + ": …"
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

const tricky = `multi: |
  line one
  line two: with colon
folded: >
  folded text
uni: "héllo — 🐝 ünïcode"
quoted: "it's \"quoted\""
numstr: "0123"
yes_str: "yes"
no_plain: no
dotted.key: v
"key: with colon": v2
neg: -7
sci: 1e3
big_float: 12345678.125
bool_false: false
long: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
nested_lists:
  - - a
    - b
  - []
  - {}
`

func TestTrickyValuesBothWays(t *testing.T) {
	id := newID(t)
	// Reference: what sops itself gives back after its own round trip
	// (e.g. 1e3 comes back as 1000 — a sops/YAML trait, not ours).
	theirs := runSops(t, id, []byte(tricky), "--encrypt", "--age", id.Recipient().String())
	want := asAny(t, runSops(t, id, theirs, "--decrypt"))
	ours, err := Encrypt([]byte(tricky), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if got := asAny(t, runSops(t, id, ours, "--decrypt")); !reflect.DeepEqual(got, want) {
		t.Fatalf("sops reading ours:\n got %#v\nwant %#v", got, want)
	}
	plain, err := Decrypt(theirs, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := asAny(t, plain); !reflect.DeepEqual(got, want) {
		t.Fatalf("us reading sops:\n got %#v\nwant %#v", got, want)
	}
}
