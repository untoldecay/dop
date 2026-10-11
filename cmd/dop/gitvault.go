package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vaultgit"
)

// Vault repo git runs in-process (internal/vaultgit, dop-bki): dop works
// without git installed. DOP_GIT_BINARY=1 restores the git shell-out
// during the transition. runGit keeps its git-style arguments so call
// sites didn't change; gitInProcess maps the exact commands dop sends.

func gitInProcess() bool { return os.Getenv("DOP_GIT_BINARY") != "1" }

var errGitUnmapped = errors.New("unmapped git command")

func initVaultGitCredentials() {
	if vaultgit.CredentialsPath != "" {
		return
	}
	if paths, err := config.Resolve(); err == nil {
		vaultgit.CredentialsPath = filepath.Join(paths.Root, "repo-credentials.json")
	}
}

// gitDo runs one git-style command in-process. A command dop never
// sends returns errGitUnmapped (the caller falls back to git, if any).
func gitDo(out io.Writer, dir string, args []string) error {
	initVaultGitCredentials()
	if len(args) == 0 {
		return errGitUnmapped
	}
	switch args[0] {
	case "init":
		if len(args) == 3 && args[1] == "--bare" {
			return vaultgit.InitBare(args[2])
		}
	case "clone":
		if len(args) == 3 {
			return vaultgit.Clone(args[1], args[2])
		}
		return errGitUnmapped
	}
	g, err := vaultgit.Open(dir)
	if err != nil {
		return err
	}
	switch {
	case eqArgs(args, "pull", "--ff-only"):
		return g.PullFFOnly()
	case eqArgs(args, "fetch", "origin"), eqArgs(args, "fetch"):
		return g.Fetch()
	case len(args) == 3 && args[0] == "merge" && args[1] == "--ff-only":
		return g.FastForward(args[2])
	case len(args) == 7 && args[0] == "merge" && args[1] == "-s" && args[2] == "ours" && args[4] == "--no-ff" && args[5] == "-m":
		return g.MergeOurs(args[3], args[6])
	case len(args) == 5 && args[0] == "log" && args[1] == "--oneline" && args[2] == "-n":
		n, _ := strconv.Atoi(args[3])
		from, to, ok := strings.Cut(args[4], "..")
		if !ok {
			return errGitUnmapped
		}
		return g.LogOneline(out, from, to, n)
	case len(args) == 3 && args[0] == "reset" && args[1] == "--hard":
		return g.ResetHard(args[2])
	case args[0] == "add":
		var paths []string
		for _, a := range args[1:] {
			if a != "-A" {
				paths = append(paths, a)
			}
		}
		return g.Add(paths...)
	case args[0] == "commit":
		msg, allowEmpty := "", false
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "-m":
				if i+1 < len(args) {
					msg = args[i+1]
					i++
				}
			case "--allow-empty":
				allowEmpty = true
			default:
				return errGitUnmapped
			}
		}
		return g.Commit(msg, allowEmpty)
	case eqArgs(args, "push"):
		return g.Push(false)
	case eqArgs(args, "push", "--force-with-lease"):
		return g.Push(true)
	}
	return errGitUnmapped
}

func eqArgs(args []string, want ...string) bool {
	if len(args) != len(want) {
		return false
	}
	for i := range want {
		if args[i] != want[i] {
			return false
		}
	}
	return true
}

// gitExec is the shell-out path (DOP_GIT_BINARY=1, or a command
// gitDo doesn't map).
func gitExec(out io.Writer, dir string, args []string) error {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// gitRun runs a git-style command: in-process when possible.
func gitRun(out io.Writer, dir string, args []string) error {
	if gitInProcess() {
		err := gitDo(out, dir, args)
		if !errors.Is(err, errGitUnmapped) {
			return err
		}
		if _, lerr := exec.LookPath("git"); lerr != nil {
			return fmt.Errorf("dop can't run `git %s` in-process and git isn't installed", strings.Join(args, " "))
		}
	}
	return gitExec(out, dir, args)
}

// gitShow returns path's content at rev (`git show rev:path`).
func gitShow(dir, rev, path string) ([]byte, error) {
	if gitInProcess() {
		g, err := vaultgit.Open(dir)
		if err != nil {
			return nil, err
		}
		return g.Show(rev, path)
	}
	cmd := exec.Command("git", "show", rev+":"+path)
	cmd.Dir = dir
	return cmd.Output()
}

// runVaultLogin — `dop vault login <host>`: store a token dop uses to
// reach the vault repo over https (no git or credential helper needed).
// The token is read from stdin, or typed without echo on a terminal.
func runVaultLogin(args []string) int {
	fs := flag.NewFlagSet("vault login", flag.ExitOnError)
	user := fs.String("user", "", "username for the token (default: any — GitHub/GitLab accept tokens with any name)")
	_ = fs.Parse(args)
	host := fs.Arg(0)
	if host == "" {
		if paths, err := config.Resolve(); err == nil {
			if g, err := vaultgit.Open(paths.Vault); err == nil {
				host = vaultgit.Host(g.RemoteURL())
			}
		}
	}
	if host == "" {
		fmt.Fprintln(os.Stderr, "usage: dop vault login <host>   (e.g. github.com) — token on stdin")
		return 2
	}
	initVaultGitCredentials()
	var token string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "Token for %s (input hidden): ", host)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop vault login: %v\n", err)
			return 1
		}
		token = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "dop vault login: %v\n", err)
			return 1
		}
		token = line
	}
	token = strings.TrimSpace(token)
	if token == "" {
		fmt.Fprintln(os.Stderr, "dop vault login: empty token")
		return 1
	}
	if err := vaultgit.SaveToken(host, *user, token); err != nil {
		fmt.Fprintf(os.Stderr, "dop vault login: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop vault login: token saved for %s (%s, readable only by you).\n", host, vaultgit.CredentialsPath)
	return 0
}

func runVaultLogout(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop vault logout <host>")
		return 2
	}
	initVaultGitCredentials()
	if err := vaultgit.ForgetToken(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "dop vault logout: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop vault logout: no stored token for %s anymore.\n", args[0])
	return 0
}
