package teamops

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAddRecipient_Idempotent(t *testing.T) {
	cfg := &SopsConfig{
		CreationRules: []SopsRule{
			{PathRegex: `.*\.yaml$`, Age: "age1existing"},
		},
	}
	if !AddRecipient(cfg, "age1new") {
		t.Fatal("expected change on first add")
	}
	if AddRecipient(cfg, "age1new") {
		t.Fatal("second add should be a no-op")
	}
	// Sorted; both should be present
	if !strings.Contains(cfg.CreationRules[0].Age, "age1existing") {
		t.Fatal("original recipient lost")
	}
	if !strings.Contains(cfg.CreationRules[0].Age, "age1new") {
		t.Fatal("new recipient not present")
	}
}

func TestRemoveRecipient(t *testing.T) {
	cfg := &SopsConfig{
		CreationRules: []SopsRule{
			{PathRegex: `.*\.yaml$`, Age: "age1alice,age1bob"},
		},
	}
	if !RemoveRecipient(cfg, "age1bob") {
		t.Fatal("expected change on remove")
	}
	if strings.Contains(cfg.CreationRules[0].Age, "age1bob") {
		t.Fatal("removed recipient still present")
	}
	if !strings.Contains(cfg.CreationRules[0].Age, "age1alice") {
		t.Fatal("other recipient dropped")
	}
	if RemoveRecipient(cfg, "age1bob") {
		t.Fatal("second remove should be a no-op")
	}
}

const teamFixture = `schema_version: 1

integrations:
  boiler:
    tokens:
      read:
        value: "blr_ro_x"
        scope_note: "read-only"
      write:
        value: "blr_rw_x"
        scope_note: "read+write"
  notion:
    tokens:
      read:
        value: "ntn_ro_x"
        scope_note: "read-only"

grants:
  boiler.read:
    integration: boiler
    token: read
  boiler.write:
    integration: boiler
    token: write
  notion.read:
    integration: notion
    token: read
`

func mustParse(t *testing.T, s string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

func TestBuildChecklist(t *testing.T) {
	root := mustParse(t, teamFixture)
	cl := BuildChecklist(root, "alice")
	// Expect 3 items: boiler.read, boiler.write, notion.read
	if len(cl.Items) != 3 {
		t.Fatalf("expected 3 rotation items, got %d: %+v", len(cl.Items), cl.Items)
	}
	// Verify decoration by grants
	m := map[string][]string{}
	for _, it := range cl.Items {
		m[it.Integration+"."+it.Token] = it.Grants
	}
	if got := m["boiler.write"]; len(got) != 1 || got[0] != "boiler.write" {
		t.Fatalf("boiler.write grant decoration missing: %v", got)
	}
}

func TestBuildChecklist_Print(t *testing.T) {
	root := mustParse(t, teamFixture)
	cl := BuildChecklist(root, "alice")
	var buf bytes.Buffer
	cl.Print(&buf)
	s := buf.String()
	for _, want := range []string{"alice", "boiler.tokens.read", "boiler.tokens.write", "notion.tokens.read", "rotate"} {
		if !strings.Contains(s, want) {
			t.Fatalf("checklist missing %q:\n%s", want, s)
		}
	}
}

func TestEnsureAndRemoveTeamMember(t *testing.T) {
	root := mustParse(t, teamFixture)
	EnsureTeamMember(root, "alice", "age1alicepub", "second engineer", "cam@fray.co")

	// Round-trip to prove the tree serializes
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		t.Fatal(err)
	}
	enc.Close()
	if !strings.Contains(buf.String(), "age1alicepub") {
		t.Fatalf("pubkey not in emitted YAML:\n%s", buf.String())
	}

	removed := RemoveTeamMember(root, "alice")
	if removed != "age1alicepub" {
		t.Fatalf("RemoveTeamMember returned %q, want age1alicepub", removed)
	}
	if RemoveTeamMember(root, "alice") != "" {
		t.Fatal("second remove should return empty")
	}
}
