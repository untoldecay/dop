package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fray/dop/internal/config"
)

func skillFreshEnv(t *testing.T) *config.Paths {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("DOP_HOME", filepath.Join(dir, "dop"))
	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// ageRecord makes the install at path look written by an older dop.
func ageRecord(t *testing.T, paths *config.Paths, path string) {
	t.Helper()
	list := loadSkillInstalls(paths)
	for i := range list {
		if list[i].Path == path {
			list[i].TemplateSHA, list[i].Version = "000000000000", "v0.0.1"
		}
	}
	if err := saveSkillInstalls(paths, list); err != nil {
		t.Fatal(err)
	}
}

func stderrOf(t *testing.T, f func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = old
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestRenderedSkillKeepsFrontmatterFirst(t *testing.T) {
	s := renderedSkill()
	if !strings.HasPrefix(s, "---\nname: dop-credential-access\n") {
		t.Fatalf("frontmatter must stay first:\n%s", s[:120])
	}
	if !strings.Contains(s, "\n`"+skillStamp()+"`\n") {
		t.Fatal("stamp missing")
	}
}

func TestSkillInstallRecordedAndFresh(t *testing.T) {
	paths := skillFreshEnv(t)
	target := filepath.Join(t.TempDir(), "SKILL.md")
	stderrOf(t, func() {
		if err := installFile(target, renderedSkill(), "skill", false); err != nil {
			t.Fatal(err)
		}
	})
	list := loadSkillInstalls(paths)
	if len(list) != 1 || list[0].Path != target || list[0].Kind != "skill" {
		t.Fatalf("install not recorded: %+v", list)
	}
	if s := staleSkillInstalls(paths); len(s) != 0 {
		t.Fatalf("fresh install reported stale: %+v", s)
	}
	// Untracked kinds (manifests) are not recorded.
	stderrOf(t, func() { _ = installFile(filepath.Join(t.TempDir(), "plugin.json"), "{}", "plugin:manifest", false) })
	if n := len(loadSkillInstalls(paths)); n != 1 {
		t.Fatalf("manifest recorded: %d entries", n)
	}
}

func TestSkillRefreshRewritesOnlyUnedited(t *testing.T) {
	paths := skillFreshEnv(t)
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean", "SKILL.md")
	edited := filepath.Join(dir, "edited", "SKILL.md")
	stderrOf(t, func() {
		_ = installFile(clean, renderedSkill(), "skill", false)
		_ = installFile(edited, renderedSkill(), "skill", false)
	})
	// An older dop wrote both; someone then edited one by hand.
	old := "---\nname: dop-credential-access\n---\nold rules\n"
	for _, p := range []string{clean, edited} {
		if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	list := loadSkillInstalls(paths)
	for i := range list {
		list[i].TemplateSHA, list[i].Version, list[i].FileSHA = "000000000000", "v0.0.1", fileSHA([]byte(old))
	}
	_ = saveSkillInstalls(paths, list)
	if err := os.WriteFile(edited, []byte(old+"my note\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stale := staleSkillInstalls(paths)
	if len(stale) != 2 {
		t.Fatalf("want 2 stale, got %+v", stale)
	}
	out := stderrOf(t, func() { runSkillRefresh(nil) })
	if b, _ := os.ReadFile(clean); string(b) != renderedSkill() {
		t.Fatalf("unedited install not refreshed; stderr: %s", out)
	}
	if b, _ := os.ReadFile(edited); string(b) != old+"my note\n" {
		t.Fatal("hand-edited install was overwritten")
	}
	if !strings.Contains(out, "edited since dop wrote it") {
		t.Fatalf("no notice for the edited file: %s", out)
	}
	if s := staleSkillInstalls(paths); len(s) != 1 || s[0].rec.Path != edited {
		t.Fatalf("after refresh only the edited file stays stale: %+v", s)
	}
}

func TestHintStaleSkillOncePerHour(t *testing.T) {
	paths := skillFreshEnv(t)
	target := filepath.Join(t.TempDir(), "SKILL.md")
	stderrOf(t, func() { _ = installFile(target, renderedSkill(), "skill", false) })
	if out := stderrOf(t, func() { hintStaleSkill("dop exec") }); out != "" {
		t.Fatalf("hint on a fresh install: %s", out)
	}
	ageRecord(t, paths, target)
	out := stderrOf(t, func() { hintStaleSkill("dop exec") })
	if !strings.Contains(out, target) || !strings.Contains(out, "v0.0.1") || !strings.Contains(out, "dop skill install --force") {
		t.Fatalf("hint missing details: %s", out)
	}
	if again := stderrOf(t, func() { hintStaleSkill("dop exec") }); again != "" {
		t.Fatalf("hint repeated within the hour: %s", again)
	}
}

func TestLegacyDefaultInstallAdoptedAndRefreshed(t *testing.T) {
	paths := skillFreshEnv(t)
	dir, _ := skillDir()
	target := filepath.Join(dir, "SKILL.md")
	old := "---\nname: dop-credential-access\n---\nDOP_TOKEN is unset: decline\n"
	_ = os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(target, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := stderrOf(t, func() { hintStaleSkill("dop exec") }); !strings.Contains(out, target) {
		t.Fatalf("legacy install not hinted: %q", out)
	}
	stderrOf(t, func() { runSkillRefresh(nil) })
	if b, _ := os.ReadFile(target); string(b) != renderedSkill() {
		t.Fatal("legacy install not refreshed")
	}
	if b, _ := os.ReadFile(target + ".before-refresh"); string(b) != old {
		t.Fatal("legacy content not kept beside the refreshed file")
	}
	if s := staleSkillInstalls(paths); len(s) != 0 {
		t.Fatalf("still stale after refresh: %+v", s)
	}
}
