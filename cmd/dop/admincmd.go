// CLI dispatch for `dop admin ...`. Kept in its own file to keep main.go
// from bloating.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

func runAdmin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop admin <init|login|logout|status|join|set-approval>")
		return 2
	}
	switch args[0] {
	case "init":
		return runAdminInit(args[1:])
	case "login":
		return runAdminLogin(args[1:])
	case "logout":
		return runAdminLogout(args[1:])
	case "status":
		return runAdminStatus(args[1:])
	case "set-approval":
		return runAdminSetApproval(args[1:])
	case "join":
		return runAdminJoin(args[1:])
	case "reset":
		return runAdminReset(args[1:])
	case "__session-daemon":
		// Internal: fork target from `dop admin login`. Not shown in help.
		return runAdminSessionDaemon(args[1:])
	case "__gui-unlock":
		// rc7h — hidden entrypoint. Called by the TUI when it detects a
		// locked admin session mid-flow. Pops the osascript passphrase
		// dialog (same shape as rc6k's auto-unlock on `dop use`), forks
		// the session daemon, exits 0 on success / non-zero on cancel
		// or dialog unavailable. Not shown in help.
		return runAdminGUIUnlock(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop admin: unknown subcommand %q\n", args[0])
		return 2
	}
}

// runAdminInit generates a fresh admin keypair (age + ed25519), wraps
// with a passphrase, writes to disk. One-shot.
func runAdminInit(args []string) int {
	fs := flag.NewFlagSet("admin init", flag.ExitOnError)
	pfromStdin := fs.Bool("passphrase-stdin", false, "read passphrase from stdin (testing only)")
	force := fs.Bool("force", false, "overwrite existing admin key (DESTRUCTIVE — loses vault access)")
	_ = fs.Parse(args)

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
		return 1
	}
	if admin.KeyFileExists(paths) && !*force {
		fmt.Fprintf(os.Stderr, "dop admin init: admin key already exists at %s\n", admin.KeyFile(paths))
		fmt.Fprintln(os.Stderr, "  Use --force to overwrite (this permanently loses access to any vault this key decrypts).")
		return 1
	}

	pass1, err := readPassphrase("Choose a passphrase for your admin key: ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
		return 1
	}
	if len(pass1) < 8 {
		fmt.Fprintln(os.Stderr, "dop admin init: passphrase must be at least 8 characters")
		return 1
	}
	if !*pfromStdin {
		pass2, err := readPassphrase("Confirm passphrase: ", false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
			return 1
		}
		if pass1 != pass2 {
			fmt.Fprintln(os.Stderr, "dop admin init: passphrases do not match")
			return 1
		}
	}

	keys, err := admin.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
		return 1
	}
	wrapped, err := admin.Wrap(keys, pass1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
		return 1
	}
	// v1.6 — approval passphrase, used to gate out-of-band claim
	// approvals (web + CLI). Distinct from the admin passphrase so we
	// never ask the user to type the master secret into a phone form.
	//
	// v1.10.5 — read the approval passphrase BEFORE writing admin.age.enc
	// so a validation failure here leaves the install completely clean
	// instead of half-baked. Prior behaviour wrote the admin key then
	// bailed on the approval check, stranding the user with an unlocked
	// admin key but no approval passphrase, and a confusing error.
	appPass1, err := readPassphrase("Choose an approval passphrase — a SEPARATE secret you type on your phone to approve agent claims (used by 'dop approve'): ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin init: approval passphrase: %v\n", err)
		return 1
	}
	if appPass1 == "" {
		fmt.Fprintln(os.Stderr, "dop admin init: approval passphrase is required.")
		fmt.Fprintln(os.Stderr, "  This is a SECOND, separate secret from the admin passphrase you just chose.")
		fmt.Fprintln(os.Stderr, "  You'll type this one on your phone to approve agent claims.")
		fmt.Fprintln(os.Stderr, "  Must be at least 10 characters. (If you're using --passphrase-stdin, feed TWO lines.)")
		return 1
	}
	if len(appPass1) < 10 {
		fmt.Fprintf(os.Stderr, "dop admin init: approval passphrase must be at least 10 characters (got %d).\n", len(appPass1))
		return 1
	}
	if !*pfromStdin {
		appPass2, err := readPassphrase("Confirm approval passphrase: ", false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
			return 1
		}
		if appPass1 != appPass2 {
			fmt.Fprintln(os.Stderr, "dop admin init: approval passphrases do not match")
			return 1
		}
	}

	// All validation passed — now write both artifacts. If either step
	// fails past this point we roll back to a clean slate so the user
	// isn't stranded in a half-installed state.
	if err := admin.WriteFile(admin.KeyFile(paths), wrapped); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin init: %v\n", err)
		return 1
	}
	if err := approval.Set(paths, appPass1); err != nil {
		// Roll back the admin key so `dop admin init` can be retried
		// from scratch without needing --force.
		_ = os.Remove(admin.KeyFile(paths))
		fmt.Fprintf(os.Stderr, "dop admin init: store approval passphrase: %v\n", err)
		fmt.Fprintln(os.Stderr, "  rolled back admin key — safe to retry.")
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop admin init: wrote %s (mode 0600)\n", admin.KeyFile(paths))
	fmt.Fprintf(os.Stderr, "  admin ed25519 pubkey: %s\n", keys.AdminPubkey())
	fmt.Fprintf(os.Stderr, "  vault decryption age recipient: %s\n", keys.Age.Recipient().String())
	fmt.Fprintln(os.Stderr, "  approval passphrase stored (keys/approval.hash)")
	return 0
}

// runAdminSetApproval (re)sets the approval passphrase without touching
// the admin key. Useful if the passphrase leaks or the user wants to
// rotate. Requires an active admin session — otherwise a same-uid
// attacker could silently swap the passphrase and then self-approve
// pending claims.
func runAdminSetApproval(args []string) int {
	fs := flag.NewFlagSet("admin set-approval", flag.ExitOnError)
	pfromStdin := fs.Bool("passphrase-stdin", false, "read passphrase from stdin (testing only)")
	_ = fs.Parse(args)

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin set-approval: %v\n", err)
		return 1
	}
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		fmt.Fprintln(os.Stderr, "dop admin set-approval: no active admin session — run `dop admin login` first")
		return 1
	}
	pass1, err := readPassphrase("New approval passphrase: ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin set-approval: %v\n", err)
		return 1
	}
	if len(pass1) < 10 {
		fmt.Fprintln(os.Stderr, "dop admin set-approval: passphrase must be at least 10 characters")
		return 1
	}
	if !*pfromStdin {
		pass2, err := readPassphrase("Confirm: ", false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop admin set-approval: %v\n", err)
			return 1
		}
		if pass1 != pass2 {
			fmt.Fprintln(os.Stderr, "dop admin set-approval: passphrases do not match")
			return 1
		}
	}
	if err := approval.Set(paths, pass1); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin set-approval: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop admin set-approval: stored")
	return 0
}

// runAdminLogin prompts passphrase, unwraps keys, forks the session daemon.
func runAdminLogin(args []string) int {
	fs := flag.NewFlagSet("admin login", flag.ExitOnError)
	pfromStdin := fs.Bool("passphrase-stdin", false, "read passphrase from stdin (testing only)")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	client := admin.NewClient(admin.SockPath(paths))
	if client.SessionActive() {
		fmt.Fprintln(os.Stderr, "dop admin login: session already active — run `dop admin status` or `dop admin logout`")
		return 1
	}

	pass, err := readPassphrase("Passphrase: ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin login: %v\n", err)
		return 1
	}
	if err := performAdminLogin(paths, pass); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin login: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop admin login: session started")
	// autoPullVault + sweepLegacyGrace run inside performAdminLogin.
	return 0
}

// performAdminLogin unwraps the admin keys with the given passphrase
// and forks the session daemon. Returns once the daemon has signaled
// `ready`. Factored out of runAdminLogin so the auto-unlock path can
// reuse the same bootstrap without duplicating the fork/pipe dance.
//
// Zeroes the passphrase byte slice on exit — the caller's string
// copy still exists but has no way to be scrubbed; we at least kill
// our own.
func performAdminLogin(paths *config.Paths, passphrase string) error {
	keys, err := admin.LoadAndUnwrap(paths, passphrase)
	if err != nil {
		return err
	}
	daemonInput, err := encodeKeysForDaemon(keys)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "admin", "__session-daemon", "--sock", admin.SockPath(paths))
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
	// rc7l — thread the operator's AdminIdleTTL pref through to the
	// daemon via DOP_ADMIN_TTL. The daemon reads env on startup; this
	// is the only hook we have without changing the daemon RPC shape.
	// Only override when the operator explicitly set a non-default; a
	// zero AdminIdleTTLSeconds means "use whatever the daemon's own
	// default is" so pre-rc7l configs continue to behave identically.
	if prefs := userprefs.Load(paths); prefs.AdminIdleTTLSeconds != 0 {
		cmd.Env = append(cmd.Env, "DOP_ADMIN_TTL="+prefs.EffectiveAdminIdleTTL().String())
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("fork: %w", err)
	}
	if _, err := stdin.Write(daemonInput); err != nil {
		return fmt.Errorf("write daemon input: %w", err)
	}
	stdin.Close()
	buf := make([]byte, 64)
	deadline := time.Now().Add(5 * time.Second)
	stdout.(interface{ SetDeadline(time.Time) error }).SetDeadline(deadline)
	n, err := stdout.Read(buf)
	if err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("daemon did not signal ready: %w", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "ready") {
		cmd.Process.Kill()
		return fmt.Errorf("unexpected daemon output: %q", string(buf[:n]))
	}
	if err := cmd.Process.Release(); err != nil {
		// Non-fatal — daemon is already running; parent-side release failure
		// just means the parent keeps a zombie child reference until exit.
		fmt.Fprintf(os.Stderr, "dop admin login: release: %v\n", err)
	}
	autoPullVault(paths)
	if n, err := sweepLegacyGrace(paths); err == nil && n > 0 {
		fmt.Fprintf(os.Stderr, "dop admin login: swept %d expired legacy agent key(s).\n", n)
	}
	return nil
}

// runAdminGUIUnlock — rc7h hidden entrypoint. Called by the TUI when
// it detects a locked admin session mid-flow. Delegates to
// autoUnlockPrompt (same osascript dialog as rc6k's `dop use`
// auto-unlock); exits 0 on success, non-zero on cancel or when the
// dialog isn't reachable (non-darwin / headless / no GUI).
//
// The TUI shells out to this instead of calling autoUnlockPrompt
// directly because internal/tui can't import cmd/dop.
func runAdminGUIUnlock(args []string) int {
	fs := flag.NewFlagSet("admin __gui-unlock", flag.ExitOnError)
	title := fs.String("title", "DOP admin unlock", "dialog title")
	body := fs.String("body", "Enter admin passphrase to unlock the session.", "dialog body")
	_ = fs.Parse(args)
	paths, _ := config.Resolve()
	client := admin.NewClient(admin.SockPath(paths))
	if client.SessionActive() {
		// Nothing to do — session already active (race between TUI's
		// check and this subprocess start).
		return 0
	}
	if _, err := autoUnlockPrompt(paths, *title, *body); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// runAdminLogout kills the session daemon via the socket.
func runAdminLogout(args []string) int {
	paths, _ := config.Resolve()
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		fmt.Fprintln(os.Stderr, "dop admin logout: no active session")
		return 0
	}
	if err := client.Logout(); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin logout: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop admin logout: session ended")
	return 0
}

// runAdminStatus prints current session state.
func runAdminStatus(args []string) int {
	paths, _ := config.Resolve()
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		fmt.Println("locked (no active session)")
		return 0
	}
	st, err := client.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin status: %v\n", err)
		return 1
	}
	idleRemaining := time.Duration(st.IdleTTLSeconds)*time.Second -
		time.Since(time.Unix(st.LastActivityUnix, 0))
	absRemaining := time.Duration(st.AbsTTLSeconds)*time.Second -
		time.Since(time.Unix(st.StartedAtUnix, 0))
	if idleRemaining < 0 {
		idleRemaining = 0
	}
	if absRemaining < 0 {
		absRemaining = 0
	}
	fmt.Println("unlocked")
	fmt.Printf("  version:          %s\n", versionString())
	fmt.Printf("  admin pubkey:     %s\n", st.AdminPubkey)
	fmt.Printf("  age recipient:    %s\n", st.AgeRecipient)
	fmt.Printf("  idle TTL left:    %s\n", roundDur(idleRemaining))
	fmt.Printf("  absolute TTL left: %s\n", roundDur(absRemaining))
	// v1.11 — one-line summary of agent-key storage across all
	// claimed bearers on this machine.
	if summary := agentKeysSummary(paths); summary != "" {
		fmt.Printf("  agent keys:       %s\n", summary)
	}
	return 0
}

// agentKeysSummary returns a compact "SE=N file=M (K pending migration)"
// line, or the empty string if there are no agent keys. Called from
// admin status + doctor.
func agentKeysSummary(paths *config.Paths) string {
	entries, err := collectAgentKeys(paths)
	if err != nil || len(entries) == 0 {
		return ""
	}
	seCount, fileCount, pending := 0, 0, 0
	for _, e := range entries {
		if e.Backend == "keychain-darwin" {
			seCount++
		} else {
			fileCount++
		}
		if e.PendingDelete {
			pending++
		}
	}
	out := fmt.Sprintf("SE=%d file=%d", seCount, fileCount)
	if pending > 0 {
		out += fmt.Sprintf(" (%d pending grace-delete)", pending)
	}
	return out
}

// runAdminSessionDaemon is the daemon-side entry: read keys from stdin,
// start the session, print "ready\n" once listening, block until end.
func runAdminSessionDaemon(args []string) int {
	fs := flag.NewFlagSet("admin __session-daemon", flag.ExitOnError)
	sockPath := fs.String("sock", "", "unix socket path")
	_ = fs.Parse(args)
	if *sockPath == "" {
		return 2
	}

	keys, err := decodeKeysFromStdin()
	if err != nil {
		return 1
	}
	// TTLs from env, with defaults.
	idle := envDuration("DOP_ADMIN_TTL", admin.DefaultIdleTTL)
	abs := envDuration("DOP_ADMIN_MAX_TTL", admin.DefaultAbsTTL)
	// v1.14.0-rc4 — Paths needed for the approval-popup RPC (daemon
	// reads approval.hash to verify the typed passphrase).
	paths, _ := config.Resolve()
	s, err := admin.StartSession(admin.SessionOpts{
		Keys:     keys,
		Paths:    paths,
		SockPath: *sockPath,
		IdleTTL:  idle,
		AbsTTL:   abs,
	})
	if err != nil {
		return 1
	}
	// Signal readiness to parent, then close stdout so parent's Read returns.
	fmt.Println("ready")
	os.Stdout.Close()
	// Detach stderr too so future writes go nowhere (log file could be
	// a later polish; for now silence is fine).
	os.Stderr.Close()
	s.Wait()
	return 0
}

// --- helpers ---

// readPassphrase reads a passphrase from the TTY without echo, or from
// stdin if fromStdin is set.
func readPassphrase(prompt string, fromStdin bool) (string, error) {
	if fromStdin {
		var buf strings.Builder
		b := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(b)
			if n == 0 || err != nil {
				break
			}
			if b[0] == '\n' {
				break
			}
			buf.WriteByte(b[0])
		}
		return strings.TrimRight(buf.String(), "\r"), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func roundDur(d time.Duration) string {
	if d >= time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// encodeKeysForDaemon writes a JSON blob suitable for
// decodeKeysFromStdin on the daemon side. Keys travel plaintext through
// the process's stdin pipe — the daemon is same-user and short-lived.
type daemonKeyBlob struct {
	AgeSecret     string `json:"age_secret"`
	Ed25519Secret string `json:"ed25519_secret_hex"`
}

func encodeKeysForDaemon(k *admin.Keys) ([]byte, error) {
	blob := daemonKeyBlob{
		AgeSecret:     k.Age.String(),
		Ed25519Secret: hexEncode(k.Ed25519),
	}
	return json.Marshal(blob)
}

func decodeKeysFromStdin() (*admin.Keys, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	var blob daemonKeyBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, err
	}
	return admin.KeysFromComponents(blob.AgeSecret, blob.Ed25519Secret)
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = digits[x>>4]
		out[i*2+1] = digits[x&0xF]
	}
	return string(out)
}
