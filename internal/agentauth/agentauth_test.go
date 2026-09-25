package agentauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/fray/dop/internal/vault"
)

func writeKeyfile(t *testing.T, dir, name string, id *age.X25519Identity) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeVault(pubkey string) *vault.Vault {
	return &vault.Vault{
		SchemaVersion: 1,
		AgentPubkeys: map[string]vault.AgentPubkey{
			"buzz-alpha": {
				PubkeyAge: pubkey,
				Grants:    []string{"boiler.read"},
			},
		},
	}
}

func TestVerify_Success(t *testing.T) {
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyfile := writeKeyfile(t, dir, "alpha.age", id)
	v := makeVault(id.Recipient().String())

	grants, err := Verify(v, "buzz-alpha", keyfile)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(grants) != 1 || grants[0] != "boiler.read" {
		t.Fatalf("unexpected grants: %v", grants)
	}
}

func TestVerify_PubkeyMismatch(t *testing.T) {
	dir := t.TempDir()
	// Generate two keypairs; keyfile is alpha, vault lists beta.
	alpha, _ := age.GenerateX25519Identity()
	beta, _ := age.GenerateX25519Identity()
	keyfile := writeKeyfile(t, dir, "alpha.age", alpha)
	v := makeVault(beta.Recipient().String())

	_, err := Verify(v, "buzz-alpha", keyfile)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match vault entry") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}

func TestVerify_UnknownAgent(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	keyfile := writeKeyfile(t, dir, "alpha.age", id)
	v := makeVault(id.Recipient().String()) // has "buzz-alpha" only

	_, err := Verify(v, "buzz-unknown", keyfile)
	if err == nil || !strings.Contains(err.Error(), "no agent_pubkeys entry") {
		t.Fatalf("expected unknown-agent error, got %v", err)
	}
}

func TestVerify_MissingKeyFile(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	v := makeVault(id.Recipient().String())

	_, err := Verify(v, "buzz-alpha", "/no/such/path.age")
	if err == nil || !strings.Contains(err.Error(), "open sign-with keyfile") {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestVerify_EmptyArgs(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	v := makeVault(id.Recipient().String())

	if _, err := Verify(v, "", "/some/path"); err == nil {
		t.Fatal("expected error on empty agent-name")
	}
	if _, err := Verify(v, "buzz-alpha", ""); err == nil {
		t.Fatal("expected error on empty keyfile")
	}
}
