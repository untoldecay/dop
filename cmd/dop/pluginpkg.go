// Local Claude Code marketplace plugin packaging — v1.14.0-rc7e.
//
// Context (cam-opus handoff 4cca9621 finding [A]):
//
// The Orca harness (and future plugin-only Claude Code builds) silently
// ignore skills under ~/.claude/skills/*/SKILL.md and commands under
// ~/.claude/commands/*.md. Only built-in binary skills + marketplace
// plugins show up in the skill selector. So `dop skill install` writing
// loose files was invisible on exactly the harness Cam uses day-to-day.
//
// Fix: ALSO build a local-marketplace plugin bundle at
// ~/.claude-local-plugins/dop-tools/ and register it with the `claude`
// CLI if available. Loose files stay (for pre-plugin Claude Code +
// Cursor + aider + custom harnesses). One `dop skill install` writes
// both; one `dop admin reset` tears down both.
//
// Scope-matched: best-effort for the plugin side. If `claude` CLI is
// absent, if the install prompts fail, if the user already has a
// marketplace by this name — we log + continue. Loose files are the
// reliable fallback; the plugin is the "it works on Orca" belt.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fray/dop/internal/version"
)

// Plugin naming is load-bearing — if these change, operators who
// upgrade get a stale plugin alongside the new one until they
// manually uninstall the old. Keep stable across releases.
const (
	pluginMarketplaceName = "dop-local"
	pluginName            = "dop"
	// pluginRootDirName is the directory under ~/.claude-local-plugins/
	// where the marketplace lives. Separate from the marketplace NAME so
	// the on-disk layout and the registered name are not coupled 1:1.
	pluginRootDirName = "dop-tools"
)

// pluginRoot returns the absolute path to the marketplace root.
func pluginRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude-local-plugins", pluginRootDirName), nil
}

// installPlugin writes the marketplace + plugin files and runs the
// `claude plugin` CLI commands to register and enable the plugin.
//
// Best-effort: any failure is logged to stderr and returned nil so the
// loose-file install (the caller) can succeed on its own. The plugin
// is additive — if the CLI isn't available, the folder still exists for
// a later `claude plugin marketplace add` by the operator.
func installPlugin(force bool) error {
	root, err := pluginRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: resolve plugin root: %v (plugin install skipped)\n", err)
		return nil
	}

	// Write the marketplace + plugin manifest files + the component
	// payloads (skill + command). All go through installFile so the
	// no-op/refuse/force discipline matches the loose-file path.
	marketplaceJSON, err := renderMarketplaceJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: render marketplace.json: %v (plugin install skipped)\n", err)
		return nil
	}
	pluginJSON, err := renderPluginJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: render plugin.json: %v (plugin install skipped)\n", err)
		return nil
	}

	pluginDir := filepath.Join(root, "plugins", pluginName)
	targets := []struct {
		path    string
		content string
		kind    string
	}{
		{filepath.Join(root, ".claude-plugin", "marketplace.json"), marketplaceJSON, "plugin:marketplace"},
		{filepath.Join(pluginDir, ".claude-plugin", "plugin.json"), pluginJSON, "plugin:manifest"},
		// Skill: plugins/<name>/skills/<skill-slug>/SKILL.md. The slug
		// matches the frontmatter `name:` in skill_template.md so Claude
		// Code's namespacing lands it at /dop:dop-credential-access.
		{filepath.Join(pluginDir, "skills", "dop-credential-access", "SKILL.md"), skillTemplate, "plugin:skill"},
		// Slash command: plugins/<name>/commands/<cmd>.md → /dop:dop-use.
		{filepath.Join(pluginDir, "commands", "dop-use.md"), dopUseCommandTemplate, "plugin:command"},
	}
	for _, t := range targets {
		if err := installFile(t.path, t.content, t.kind, force); err != nil {
			fmt.Fprintf(os.Stderr, "dop skill install: plugin file %s: %v (plugin install skipped — loose files still active)\n", t.path, err)
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "dop skill install: wrote plugin bundle at %s\n", root)

	// Register + enable via the `claude` CLI. Both commands are
	// idempotent-ish — add refuses on duplicate names, install
	// refuses on already-installed. We swallow those errors silently.
	if _, err := exec.LookPath("claude"); err != nil {
		fmt.Fprintln(os.Stderr, "dop skill install: `claude` CLI not on PATH — plugin files written but NOT registered.")
		fmt.Fprintf(os.Stderr, "  Run manually when Claude Code is installed:\n")
		fmt.Fprintf(os.Stderr, "    claude plugin marketplace add %s\n", root)
		fmt.Fprintf(os.Stderr, "    claude plugin install %s@%s\n", pluginName, pluginMarketplaceName)
		return nil
	}
	// `claude plugin marketplace add <path>` registers the marketplace.
	// --yes auto-accepts any confirmation. Local paths need the ./ or
	// absolute form — pluginRoot returns absolute, which is fine.
	addCmd := exec.Command("claude", "plugin", "marketplace", "add", root)
	addCmd.Stdin = os.Stdin // in case it prompts (shouldn't, local path)
	addOut, addErr := addCmd.CombinedOutput()
	if addErr != nil && !strings.Contains(string(addOut), "already") {
		fmt.Fprintf(os.Stderr, "dop skill install: `claude plugin marketplace add` failed: %v\n", addErr)
		fmt.Fprintf(os.Stderr, "  output: %s\n", strings.TrimSpace(string(addOut)))
		// Non-fatal: files are written, operator can register manually.
		return nil
	}
	installCmd := exec.Command("claude", "plugin", "install", pluginName+"@"+pluginMarketplaceName)
	installCmd.Stdin = os.Stdin
	instOut, instErr := installCmd.CombinedOutput()
	if instErr != nil && !strings.Contains(string(instOut), "already") {
		fmt.Fprintf(os.Stderr, "dop skill install: `claude plugin install` failed: %v\n", instErr)
		fmt.Fprintf(os.Stderr, "  output: %s\n", strings.TrimSpace(string(instOut)))
		return nil
	}
	fmt.Fprintf(os.Stderr, "dop skill install: registered plugin %s@%s\n", pluginName, pluginMarketplaceName)
	fmt.Fprintln(os.Stderr, "  Restart Claude Code to activate the plugin.")
	fmt.Fprintln(os.Stderr, "  Then: /dop:dop-use <subject> <task>  (plugin-prefixed form of /dop-use)")
	return nil
}

// uninstallPlugin tears down everything installPlugin set up. Called
// from runAdminReset BEFORE wiping paths.Root so the operator gets a
// clean "DOP is gone from this machine" state.
//
// Best-effort: every step is independent; failures are logged and
// cleanup continues. Idempotent — running it when nothing is installed
// should return 0 silently.
func uninstallPlugin() {
	root, err := pluginRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin reset: resolve plugin root: %v\n", err)
		return
	}
	// Unregister via `claude` CLI if available. Both commands are
	// safe to run when the plugin isn't registered — they exit non-
	// zero with "not found" which we treat as success.
	if _, err := exec.LookPath("claude"); err == nil {
		uninstCmd := exec.Command("claude", "plugin", "uninstall", pluginName+"@"+pluginMarketplaceName)
		if out, err := uninstCmd.CombinedOutput(); err != nil {
			// Only log non-"not found" errors.
			if !strings.Contains(string(out), "not found") && !strings.Contains(string(out), "not installed") {
				fmt.Fprintf(os.Stderr, "  warning: `claude plugin uninstall`: %v\n", err)
			}
		} else {
			fmt.Fprintln(os.Stderr, "  ✓ uninstalled Claude Code plugin")
		}
		rmCmd := exec.Command("claude", "plugin", "marketplace", "remove", pluginMarketplaceName)
		if out, err := rmCmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "not found") {
				fmt.Fprintf(os.Stderr, "  warning: `claude plugin marketplace remove`: %v\n", err)
			}
		}
	}
	// Remove the plugin folder regardless of CLI outcome. If the CLI
	// uninstall failed, this at least orphans the registration (which
	// will fail on next launch and the operator can clean up manually).
	if _, err := os.Stat(root); err == nil {
		if err := os.RemoveAll(root); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: remove %s: %v\n", root, err)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ removed plugin bundle at %s\n", root)
		}
	}
	// Also clean the loose files (companion to the plugin install).
	home, _ := os.UserHomeDir()
	if home != "" {
		loose := []string{
			filepath.Join(home, ".claude", "skills", "dop"),
			filepath.Join(home, ".claude", "commands", "dop-use.md"),
		}
		for _, p := range loose {
			if _, err := os.Stat(p); err == nil {
				if err := os.RemoveAll(p); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: remove %s: %v\n", p, err)
				} else {
					fmt.Fprintf(os.Stderr, "  ✓ removed %s\n", p)
				}
			}
		}
	}
}

// renderMarketplaceJSON returns the marketplace.json content for the
// DOP local marketplace. Version comes from the dop binary's build-
// time version string so an upgraded dop install cleanly supersedes
// a stale plugin on the next `dop skill install`.
func renderMarketplaceJSON() (string, error) {
	type pluginEntry struct {
		Name        string `json:"name"`
		Source      string `json:"source"`
		Description string `json:"description"`
		Version     string `json:"version"`
	}
	type owner struct {
		Name string `json:"name"`
	}
	type marketplace struct {
		Name        string        `json:"name"`
		Description string        `json:"description"`
		Version     string        `json:"version"`
		Owner       owner         `json:"owner"`
		Plugins     []pluginEntry `json:"plugins"`
	}
	m := marketplace{
		Name:        pluginMarketplaceName,
		Description: "DOP credential vault tooling (local marketplace)",
		Version:     version.Version,
		Owner:       owner{Name: "DOP operator (local)"},
		Plugins: []pluginEntry{{
			Name:        pluginName,
			Source:      "./plugins/" + pluginName,
			Description: "DOP vault — safe eval + /dop-use slash command",
			Version:     version.Version,
		}},
	}
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf) + "\n", nil
}

// renderPluginJSON returns the per-plugin manifest. Keeps `name`
// stable; version tracks the dop binary.
func renderPluginJSON() (string, error) {
	type author struct {
		Name string `json:"name"`
	}
	type manifest struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
		Author      author `json:"author"`
	}
	m := manifest{
		Name:        pluginName,
		Version:     version.Version,
		Description: "DOP vault — leak-safe eval, /dop-use slash command, credential-access skill",
		Author:      author{Name: "DOP operator"},
	}
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf) + "\n", nil
}
