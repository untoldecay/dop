// `dop skill install` — writes the DOP Claude Code skill into
// ~/.claude/skills/dop/SKILL.md on this machine so LLM agents know
// about the safe eval pattern + the approval popup. v1.14.0-rc6.
//
// The skill body is embedded at build time from
// cmd/dop/skill_template.md so operators can `dop skill install`
// after a fresh binary install and get the current guidance
// without needing to copy files manually across machines.

package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed skill_template.md
var skillTemplate string

func runSkill(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop skill <install|path|show>")
		return 2
	}
	switch args[0] {
	case "install":
		return runSkillInstall(args[1:])
	case "path":
		return runSkillPath(args[1:])
	case "show":
		return runSkillShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop skill: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runSkillInstall(args []string) int {
	fs := flag.NewFlagSet("skill install", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite an existing SKILL.md on this machine (default: refuse if content differs)")
	_ = fs.Parse(args)

	dir, err := skillDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: mkdir: %v\n", err)
		return 1
	}
	target := filepath.Join(dir, "SKILL.md")
	// If the file already exists AND content matches, no-op silently.
	// If it exists AND content differs, refuse unless --force.
	if existing, rerr := os.ReadFile(target); rerr == nil {
		if string(existing) == skillTemplate {
			fmt.Fprintf(os.Stderr, "dop skill install: %s is already up-to-date\n", target)
			return 0
		}
		if !*force {
			fmt.Fprintf(os.Stderr, "dop skill install: %s already exists with different content.\n", target)
			fmt.Fprintln(os.Stderr, "  Pass --force to overwrite (previous content will be replaced).")
			return 1
		}
	}
	if err := os.WriteFile(target, []byte(skillTemplate), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: write: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop skill install: wrote %s\n", target)
	fmt.Fprintln(os.Stderr, "  LLM agents on this machine will now follow the DOP safety protocol.")
	fmt.Fprintln(os.Stderr, "  Re-run `dop skill install` after upgrading dop to pick up any skill changes.")
	return 0
}

func runSkillPath(args []string) int {
	dir, err := skillDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop skill path: %v\n", err)
		return 1
	}
	fmt.Println(filepath.Join(dir, "SKILL.md"))
	return 0
}

func runSkillShow(args []string) int {
	_, err := os.Stdout.WriteString(skillTemplate)
	if err != nil {
		return 1
	}
	return 0
}

// skillDir returns ~/.claude/skills/dop. Honors $HOME.
func skillDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "skills", "dop"), nil
}
