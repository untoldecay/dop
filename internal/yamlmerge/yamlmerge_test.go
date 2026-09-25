package yamlmerge

import (
	"strings"
	"testing"
)

func TestMerge_NoChanges(t *testing.T) {
	base := "a: 1\nb: 2\n"
	res, err := Merge([]byte(base), []byte(base), []byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts: %v", res.Conflicts)
	}
}

func TestMerge_OneSideChanges(t *testing.T) {
	base := "a: 1\nb: 2\n"
	ours := "a: 1\nb: 20\n" // ours changed b
	theirs := base           // theirs unchanged
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts: %v", res.Conflicts)
	}
	out, err := EmitBytes(res.Merged)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "b: 20") {
		t.Fatalf("expected b=20 in output, got:\n%s", out)
	}
}

func TestMerge_DisjointChanges(t *testing.T) {
	base := "a: 1\nb: 2\n"
	ours := "a: 10\nb: 2\n"   // ours changed a
	theirs := "a: 1\nb: 20\n" // theirs changed b — no overlap
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts: %v", res.Conflicts)
	}
	out, err := EmitBytes(res.Merged)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "a: 10") || !strings.Contains(s, "b: 20") {
		t.Fatalf("expected both edits merged, got:\n%s", s)
	}
}

func TestMerge_BothSameEdit(t *testing.T) {
	base := "a: 1\n"
	ours := "a: 2\n"
	theirs := "a: 2\n" // both made the same edit
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts: %v", res.Conflicts)
	}
}

func TestMerge_TrueConflict(t *testing.T) {
	base := "a: 1\n"
	ours := "a: 10\n"
	theirs := "a: 20\n"
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0] != "a" {
		t.Fatalf("expected conflict at 'a', got %v", res.Conflicts)
	}
}

func TestMerge_NestedDisjoint(t *testing.T) {
	base := `
integrations:
  boiler:
    tokens:
      read:
        value: OLD_RO
      write:
        value: OLD_RW
`
	ours := `
integrations:
  boiler:
    tokens:
      read:
        value: OLD_RO
      write:
        value: NEW_RW_FROM_OURS
`
	theirs := `
integrations:
  boiler:
    tokens:
      read:
        value: NEW_RO_FROM_THEIRS
      write:
        value: OLD_RW
`
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts on disjoint nested edits: %v", res.Conflicts)
	}
	out, err := EmitBytes(res.Merged)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "NEW_RW_FROM_OURS") {
		t.Fatalf("expected ours' write edit preserved, got:\n%s", s)
	}
	if !strings.Contains(s, "NEW_RO_FROM_THEIRS") {
		t.Fatalf("expected theirs' read edit preserved, got:\n%s", s)
	}
}

func TestMerge_AddedKeys(t *testing.T) {
	base := "a: 1\n"
	ours := "a: 1\nb: 2\n"      // added b
	theirs := "a: 1\nc: 3\n"    // added c
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts on additions: %v", res.Conflicts)
	}
	out, _ := EmitBytes(res.Merged)
	s := string(out)
	if !strings.Contains(s, "b: 2") || !strings.Contains(s, "c: 3") {
		t.Fatalf("expected both additions preserved:\n%s", s)
	}
}

func TestMerge_DeletionRespectedWhenOtherSideUntouched(t *testing.T) {
	base := "a: 1\nb: 2\n"
	ours := "a: 1\n" // deleted b
	theirs := "a: 1\nb: 2\n"
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts: %v", res.Conflicts)
	}
	out, _ := EmitBytes(res.Merged)
	if strings.Contains(string(out), "b:") {
		t.Fatalf("expected b deleted, got:\n%s", out)
	}
}

func TestMerge_DeleteVsModifyIsConflict(t *testing.T) {
	base := "a: 1\nb: 2\n"
	ours := "a: 1\n" // deleted b
	theirs := "a: 1\nb: 22\n" // modified b
	res, err := Merge([]byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0] != "b" {
		t.Fatalf("expected delete/modify conflict on 'b', got %v", res.Conflicts)
	}
}
