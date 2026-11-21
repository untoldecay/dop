// Skill freshness (dop-153). An agent keeps whatever skill text it was
// given; after `dop update` it can follow rules the new dop has changed
// (dop-3o5: a claimed agent told to decline). So:
//
//   - the skill carries a stamp (`dop skill check` prints the current one),
//   - `dop skill install` records every file it writes,
//   - `dop exec` / `dop whoami` hint, at most once an hour, when a
//     recorded install predates this dop's skill,
//   - `dop update` runs the new binary's `dop skill refresh`, which
//     rewrites the installs nobody edited and leaves the rest alone.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/version"
)

// templateSHA is a short content id for an embedded template; it
// changes only when the text does, not on every version bump.
func templateSHA(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])[:12]
}

func fileSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func skillStamp() string {
	return fmt.Sprintf("dop-skill: %s sha:%s", version.Version, templateSHA(skillTemplate))
}

// renderedSkill is the skill as dop installs and shows it: the stamp
// sits right after the frontmatter so a hand-copied file carries it too.
func renderedSkill() string {
	stamp := "`" + skillStamp() + "`\n"
	if strings.HasPrefix(skillTemplate, "---\n") {
		if end := strings.Index(skillTemplate[4:], "\n---\n"); end >= 0 {
			cut := 4 + end + len("\n---\n")
			return skillTemplate[:cut] + "\n" + stamp + skillTemplate[cut:]
		}
	}
	return stamp + skillTemplate
}

// skillInstall is one file `dop skill install` wrote.
type skillInstall struct {
	Path        string    `json:"path"`
	Kind        string    `json:"kind"`
	Version     string    `json:"version"`
	TemplateSHA string    `json:"template_sha"`
	FileSHA     string    `json:"file_sha"`
	WrittenAt   time.Time `json:"written_at"`
	// Legacy: found at a default location, written by a dop that kept
	// no record (before v1.21.2). Refresh backs it up before rewriting.
	Legacy bool `json:"legacy,omitempty"`
}

// trackedKinds maps the installFile kinds worth tracking to the text
// dop would write for them now.
func trackedTemplate(kind string) (string, bool) {
	switch kind {
	case "skill", "plugin:skill":
		return renderedSkill(), true
	case "command", "plugin:command":
		return dopUseCommandTemplate, true
	}
	return "", false
}

// rawTemplateSHA is what a record compares against: the sha of the raw
// embedded template, so the version in the stamp doesn't count.
func rawTemplateSHA(kind string) string {
	if strings.HasSuffix(kind, "skill") {
		return templateSHA(skillTemplate)
	}
	return templateSHA(dopUseCommandTemplate)
}

func skillInstallsPath(paths *config.Paths) string {
	return filepath.Join(paths.Root, "skill-installs.json")
}

func skillNudgePath(paths *config.Paths) string {
	return filepath.Join(paths.Root, "skill-stale.nudged")
}

func loadSkillInstalls(paths *config.Paths) []skillInstall {
	b, err := os.ReadFile(skillInstallsPath(paths))
	if err != nil {
		return nil
	}
	var list []skillInstall
	_ = json.Unmarshal(b, &list)
	return list
}

func saveSkillInstalls(paths *config.Paths, list []skillInstall) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		return err
	}
	return os.WriteFile(skillInstallsPath(paths), append(b, '\n'), 0o600)
}

// recordSkillInstall notes that dop wrote (or found up to date) content
// at path. Best-effort: a failure here never fails the install.
func recordSkillInstall(path, kind, content string) {
	if _, ok := trackedTemplate(kind); !ok {
		return
	}
	paths, err := config.Resolve()
	if err != nil {
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	rec := skillInstall{
		Path:        abs,
		Kind:        kind,
		Version:     version.Version,
		TemplateSHA: rawTemplateSHA(kind),
		FileSHA:     fileSHA([]byte(content)),
		WrittenAt:   time.Now().UTC(),
	}
	list := loadSkillInstalls(paths)
	replaced := false
	for i := range list {
		if list[i].Path == abs {
			list[i], replaced = rec, true
		}
	}
	if !replaced {
		list = append(list, rec)
	}
	_ = saveSkillInstalls(paths, list)
	_ = os.Remove(skillNudgePath(paths))
}

// defaultSkillLocations are the files `dop skill install` writes when
// no --path is given, with the text that identifies dop's own copy.
func defaultSkillLocations() []struct{ path, kind, marker string } {
	var out []struct{ path, kind, marker string }
	if dir, err := skillDir(); err == nil {
		out = append(out, struct{ path, kind, marker string }{filepath.Join(dir, "SKILL.md"), "skill", "name: dop-credential-access"})
	}
	if p, err := dopUseCommandPath(); err == nil {
		out = append(out, struct{ path, kind, marker string }{p, "command", "DOP portable bearer"})
	}
	if root, err := pluginRoot(); err == nil {
		pd := filepath.Join(root, "plugins", pluginName)
		out = append(out,
			struct{ path, kind, marker string }{filepath.Join(pd, "skills", "dop-credential-access", "SKILL.md"), "plugin:skill", "name: dop-credential-access"},
			struct{ path, kind, marker string }{filepath.Join(pd, "commands", "dop-use.md"), "plugin:command", "DOP portable bearer"})
	}
	return out
}

// adoptLegacyInstalls records dop's files at the default locations
// that an older dop wrote without a record, so the first upgrade past
// v1.21.1 still finds them. A skill carrying a stamp is never adopted:
// a current dop wrote it and recorded it, or someone copied it there.
func adoptLegacyInstalls(paths *config.Paths) {
	list := loadSkillInstalls(paths)
	known := map[string]bool{}
	for _, r := range list {
		known[r.Path] = true
	}
	added := false
	for _, loc := range defaultSkillLocations() {
		if known[loc.path] {
			continue
		}
		b, err := os.ReadFile(loc.path)
		if err != nil || !strings.Contains(string(b), loc.marker) || strings.Contains(string(b), "dop-skill: ") {
			continue
		}
		cur, _ := trackedTemplate(loc.kind)
		if string(b) == cur {
			continue
		}
		list = append(list, skillInstall{
			Path: loc.path, Kind: loc.kind, Version: "an older dop", TemplateSHA: "legacy",
			FileSHA: fileSHA(b), WrittenAt: time.Now().UTC(), Legacy: true,
		})
		added = true
	}
	if added {
		_ = saveSkillInstalls(paths, list)
	}
}

// staleSkill is a recorded install older than this dop's template.
type staleSkill struct {
	rec    skillInstall
	edited bool // the file changed since dop wrote it
}

// staleSkillInstalls lists recorded installs whose template predates
// this dop. Installs whose file is gone are skipped.
func staleSkillInstalls(paths *config.Paths) []staleSkill {
	var out []staleSkill
	for _, rec := range loadSkillInstalls(paths) {
		if rec.TemplateSHA == rawTemplateSHA(rec.Kind) {
			continue
		}
		b, err := os.ReadFile(rec.Path)
		if err != nil {
			continue
		}
		out = append(out, staleSkill{rec: rec, edited: fileSHA(b) != rec.FileSHA})
	}
	return out
}

// hintStaleSkill prints one line on stderr when a recorded skill
// install predates this dop, at most once an hour. cmd labels the line.
func hintStaleSkill(cmd string) {
	paths, err := config.Resolve()
	if err != nil {
		return
	}
	adoptLegacyInstalls(paths)
	stale := staleSkillInstalls(paths)
	if len(stale) == 0 {
		return
	}
	if info, err := os.Stat(skillNudgePath(paths)); err == nil && time.Since(info.ModTime()) < time.Hour {
		return
	}
	_ = os.WriteFile(skillNudgePath(paths), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	first := stale[0].rec
	more := ""
	if len(stale) > 1 {
		more = fmt.Sprintf(" (and %d more)", len(stale)-1)
	}
	fmt.Fprintf(os.Stderr, "%s: the DOP skill at %s%s is from %s; this dop is %s. Follow `dop skill show` for now, and ask the operator to run `dop skill install --force`.\n",
		cmd, first.Path, more, first.Version, version.Version)
}

// runSkillRefresh rewrites recorded installs that predate this dop and
// that nobody edited. `dop update` runs it from the new binary.
func runSkillRefresh(args []string) int {
	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop skill refresh: %v\n", err)
		return 1
	}
	adoptLegacyInstalls(paths)
	plugin := false
	for _, s := range staleSkillInstalls(paths) {
		if s.edited {
			fmt.Fprintf(os.Stderr, "dop skill refresh: %s was edited since dop wrote it — left alone; `dop skill install --force` replaces it\n", s.rec.Path)
			continue
		}
		content, _ := trackedTemplate(s.rec.Kind)
		if s.rec.Legacy {
			// No record of what dop wrote: keep the old file next to it.
			if old, err := os.ReadFile(s.rec.Path); err == nil {
				_ = os.WriteFile(s.rec.Path+".before-refresh", old, 0o600)
			}
		}
		if err := os.WriteFile(s.rec.Path, []byte(content), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "dop skill refresh: %s: %v\n", s.rec.Path, err)
			continue
		}
		recordSkillInstall(s.rec.Path, s.rec.Kind, content)
		fmt.Fprintf(os.Stderr, "dop skill refresh: updated %s\n", s.rec.Path)
		if strings.HasPrefix(s.rec.Kind, "plugin:") {
			plugin = true
		}
	}
	if plugin {
		refreshPluginManifest()
	}
	return 0
}

// refreshPluginManifest rewrites plugin.json (its version tracks dop)
// and asks Claude Code to pick the new files up. Best-effort.
func refreshPluginManifest() {
	root, err := pluginRoot()
	if err != nil {
		return
	}
	if pj, err := renderPluginJSON(); err == nil {
		_ = os.WriteFile(filepath.Join(root, "plugins", pluginName, ".claude-plugin", "plugin.json"), []byte(pj), 0o600)
	}
	if _, err := exec.LookPath("claude"); err != nil {
		return
	}
	_ = exec.Command("claude", "plugin", "marketplace", "update", pluginMarketplaceName).Run()
	if err := exec.Command("claude", "plugin", "update", pluginName+"@"+pluginMarketplaceName).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "dop skill refresh: run `claude plugin update %s@%s` to load the new plugin skill\n", pluginName, pluginMarketplaceName)
		return
	}
	fmt.Fprintln(os.Stderr, "dop skill refresh: plugin updated — restart Claude Code to load it")
}

// runSkillCheck prints the current stamp and the state of every
// recorded install. Read-only.
func runSkillCheck(args []string) int {
	fmt.Println(skillStamp())
	paths, err := config.Resolve()
	if err != nil {
		return 0
	}
	adoptLegacyInstalls(paths)
	stale := map[string]staleSkill{}
	for _, s := range staleSkillInstalls(paths) {
		stale[s.rec.Path] = s
	}
	for _, rec := range loadSkillInstalls(paths) {
		state := "current"
		if s, ok := stale[rec.Path]; ok {
			state = "outdated (" + rec.Version + ")"
			if s.edited {
				state += ", edited by hand"
			}
		} else if _, err := os.Stat(rec.Path); err != nil {
			state = "missing"
		}
		fmt.Printf("%-10s %s  %s\n", rec.Kind, state, rec.Path)
	}
	return 0
}
