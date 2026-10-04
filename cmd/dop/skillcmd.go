// `dop skill install` — writes the DOP Claude Code skill into
// ~/.claude/skills/dop/SKILL.md on this machine so LLM agents know
// about the safe eval pattern + the approval popup. v1.14.0-rc6.
//
// rc6g — also drops the leak-safe `/dop-use` slash command into
// ~/.claude/commands/dop-use.md alongside the skill. The slash
// command (from tester-ci-1 handoff 395b611f) wraps the safe eval
// pattern so an operator or agent can run `/dop-use <subject> <task>`
// without the transcript-leak of bare `! dop use`. Bundling it with
// the default install means every agent gets the convenience by
// default; `--path` installs skip the command (since the convention
// is Claude Code-specific).
//
// The skill body and command body are both embedded at build time
// from cmd/dop/skill_template.md + cmd/dop/dop_use_command_template.md
// so operators can `dop skill install` after a fresh binary install
// and get the current guidance without needing to copy files
// manually across machines.

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

//go:embed dop_use_command_template.md
var dopUseCommandTemplate string

func runSkill(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop skill <install|path|show|show-command>")
		return 2
	}
	switch args[0] {
	case "install":
		return runSkillInstall(args[1:])
	case "path":
		return runSkillPath(args[1:])
	case "show":
		return runSkillShow(args[1:])
	case "show-command":
		return runSkillShowCommand(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop skill: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runSkillInstall(args []string) int {
	fs := flag.NewFlagSet("skill install", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing files at the target (default: refuse if content differs)")
	// v1.14.0-rc6b — custom target path for non-Claude agents (Cursor,
	// Zed, custom harnesses, etc.). When unset, defaults to the Claude
	// Code location AND also drops ~/.claude/commands/dop-use.md.
	// Other agents can `dop skill show` + `dop skill show-command`
	// and handle install themselves.
	customPath := fs.String("path", "", "install path. Default: ~/.claude/skills/dop/SKILL.md + ~/.claude/commands/dop-use.md. Pass a specific path for Cursor / Zed / other agents (only the skill is installed; command is Claude Code-specific).")
	_ = fs.Parse(args)

	var target string
	if *customPath != "" {
		target = *customPath
	} else {
		dir, err := skillDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop skill install: %v\n", err)
			return 1
		}
		target = filepath.Join(dir, "SKILL.md")
	}
	if err := installFile(target, skillTemplate, "skill", *force); err != nil {
		fmt.Fprintf(os.Stderr, "dop skill install: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop skill install: wrote %s\n", target)

	// rc6g — on the default Claude Code install path, also drop the
	// /dop-use slash command. Skipped for --path installs because the
	// slash-command convention is Claude Code-specific; other agents
	// should fetch via `dop skill show-command` if they want it.
	if *customPath == "" {
		cmdTarget, err := dopUseCommandPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop skill install: resolve commands dir: %v\n", err)
			return 1
		}
		if err := installFile(cmdTarget, dopUseCommandTemplate, "command", *force); err != nil {
			fmt.Fprintf(os.Stderr, "dop skill install: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "dop skill install: wrote %s\n", cmdTarget)
		fmt.Fprintln(os.Stderr, "  LLM agents on this machine will now follow the DOP safety protocol.")
		fmt.Fprintln(os.Stderr, "  Operators can now run `/dop-use <subject> <task>` for leak-safe credentialed tasks.")
	}
	fmt.Fprintln(os.Stderr, "  Re-run `dop skill install` after upgrading dop to pick up any changes.")
	fmt.Fprintln(os.Stderr, "  For non-Claude agents: pass `--path <where-your-agent-reads-skills>` OR")
	fmt.Fprintln(os.Stderr, "  invoke `dop skill show` / `dop skill show-command` and let the agent install itself.")
	return 0
}

// installFile writes content to target. If the file already exists
// with matching content, no-op. If it exists with different content,
// refuse unless force. Creates parent directories at 0o700.
//
// kind is a human label ("skill" / "command") used only in the
// no-op/refuse messages so the operator can tell which file the CLI
// is reporting on.
func installFile(target, content, kind string, force bool) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", parent, err)
	}
	if existing, rerr := os.ReadFile(target); rerr == nil {
		if string(existing) == content {
			fmt.Fprintf(os.Stderr, "dop skill install: %s is already up-to-date (%s)\n", target, kind)
			return nil
		}
		if !force {
			return fmt.Errorf("%s already exists with different %s content.\n  Pass --force to overwrite (previous content will be replaced)", target, kind)
		}
	}
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
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

// runSkillShowCommand prints the /dop-use slash-command body to
// stdout. Non-Claude agents can pipe this into their own command
// directory, or operators can review the content before install.
func runSkillShowCommand(args []string) int {
	_, err := os.Stdout.WriteString(dopUseCommandTemplate)
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

// dopUseCommandPath returns ~/.claude/commands/dop-use.md. Honors $HOME.
func dopUseCommandPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "commands", "dop-use.md"), nil
}
