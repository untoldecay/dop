// Screen-walk harness: drives the root model in-process with real
// tea.KeyMsg values and dumps every reachable screen as raw ANSI so an
// external tool can rasterize a gallery. Opt-in:
//
//	DOP_TUI_WALK=<outdir> go test ./internal/tui -run TestWalkScreens -v
//
// Output: <outdir>/<NNN>-<slug>-<cols>x<rows>.ans (exactly View()) plus
// <outdir>/index.txt (filename<TAB>title<TAB>key path<TAB>tags). Tags:
// `key` (best example of a pattern), `flow:<name>`, `edge`.
//
// Key paths are the contract for the HTML lab, which replays them: list
// and menu rows are reached with down×k + enter (digits only where the
// menu is numbered), and every flow starts from launch.
//
// Nothing here runs a subprocess: every tea.Cmd returned by Update is
// dropped, PATH points at a stub dir (so View()-time pbcopy calls fail
// lookup), and async results are injected as the views' own message
// types — marked `direct:` in the key-path column.

package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
	"github.com/fray/dop/internal/userprefs"
)

const walkPubkey = "9f2c4e6a8b0d1f3e5a7c9e1b3d5f7a9c2e4f6a8b0c1d3e5f7a9b2c4d6e8f0a1b"

// walkVault — plaintext fixture (no `sops:` key), so the views'
// loaders read it straight off disk without the daemon.
var walkVault = `schema_version: "1"
admins:
  cam:
    age_recipient: age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq
    ed25519_pubkey: ` + walkPubkey + `
    added_at: 2026-01-12T09:30:00Z
    note: MacBook Pro (primary)
  alex:
    age_recipient: age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj
    ed25519_pubkey: 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
    added_at: 2026-03-02T14:00:00Z
integrations:
  notion:
    kind: api
    description: Team wiki + docs space
    metadata:
      base_url: https://api.notion.com/v1
    projects: [docs]
    tokens:
      notion:
        value: secret_ntn_4f8a
        scope_note: read-only
      notion-write:
        value: secret_ntn_9c2d
        scope_note: read-write
  github:
    kind: cli
    description: GitHub CLI for PRs and issues
    metadata:
      cli_cmd: gh
    tokens:
      github:
        value: ghp_walkfixture
        scope_note: repo
  linear:
    kind: mcp
    metadata:
      mcp_url: https://mcp.linear.app/sse
    tokens:
      linear:
        value: lin_api_walk
  acme-internal-billing-reconciliation-service-production-eu-west-1:
    kind: api
    description: Billing reconciliation (protected, long name to expose truncation)
    protected: true
    owner: ` + walkPubkey + `
    metadata:
      base_url: https://billing-reconciliation.internal.acme-corp.example.com/api/v2
    tokens:
      service-account-readonly-reporting-credential:
        value: acme_live_walk
        scope_note: read-only
grants:
  notion-read:
    integration: notion
    token: notion
    projects: [docs]
    tags: [ro]
  notion-write:
    integration: notion
    token: notion-write
    env_prefix: NOTION_NOTION # collides with notion-read's default prefix
    projects: [docs]
  github:
    integration: github
    token: github
    tags: [ci]
  linear:
    integration: linear
    token: linear
  acme-billing-reconciliation-readonly-reporting-grant-for-finance-agents:
    integration: acme-internal-billing-reconciliation-service-production-eu-west-1
    token: service-account-readonly-reporting-credential
    protected: true
    owner: ` + walkPubkey + `
capabilities:
  c0a1b2c3d4e5f6a7b8c9d0e1:
    subject: claude-code-laptop
    grants: [notion-read, github]
    created_at: 2026-10-01T10:00:00Z
    expires_at: 2026-10-08T10:00:00Z
    generation: 3
    lookup_id: a1b2c3d4e5f60718293a4b5c
    issued_by: ` + walkPubkey + `
    status: active
    portable_wrapped: YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB3YWxr
    binding:
      kind: pin
      pin_expiry: 2026-10-05T12:00:00Z
  c1b2c3d4e5f6a7b8c9d0e1f2:
    subject: codex-ci-runner
    grants: [github, linear]
    created_at: 2026-09-20T08:00:00Z
    expires_at: 9999-12-31T00:00:00Z
    generation: 3
    lookup_id: b2c3d4e5f60718293a4b5c6d
    issued_by: 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
    status: active
    binding:
      kind: pubkey
      key_type: p256
      pubkey: 04d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4
      claimed_at: 2026-09-20T08:05:00Z
  c3d4e5f6a7b8c9d0e1f2a3b4:
    subject: finance-agent
    grants: [acme-billing-reconciliation-readonly-reporting-grant-for-finance-agents]
    created_at: 2026-10-02T09:00:00Z
    expires_at: 2026-11-01T09:00:00Z
    generation: 1
    lookup_id: d4e5f60718293a4b5c6d7e8f
    issued_by: ` + walkPubkey + `
    status: active
    binding:
      kind: pin
      pin_expiry: 2026-10-07T09:00:00Z
  c2c3d4e5f6a7b8c9d0e1f2a3:
    subject: old-notion-agent
    grants: [notion-write]
    created_at: 2026-06-01T08:00:00Z
    expires_at: 2026-07-01T08:00:00Z
    generation: 1
    lookup_id: c3d4e5f60718293a4b5c6d7e
    issued_by: ` + walkPubkey + `
    status: revoked
`

const walkInvite = `{"invite_id":"3f9a0c1d2e4b5a69","name":"alex-laptop","created_at":"2026-10-04T09:00:00Z","expires_at":"2026-10-11T09:00:00Z","created_by_pub":"` + walkPubkey + `","kind":"team_member"}`

// walkVaultMany — the main fixture plus 14 extra active bearers, so the
// bearer list overflows a 24-row terminal.
func walkVaultMany() string {
	var b strings.Builder
	b.WriteString(walkVault)
	for i := 1; i <= 14; i++ {
		fmt.Fprintf(&b, "  %02xd1e2f3a4b5c6d7e8f9a0b1:\n    subject: agent-%02d-nightly-build\n    grants: [github]\n"+
			"    created_at: 2026-10-01T10:00:00Z\n    expires_at: 2026-10-08T10:00:00Z\n    generation: 1\n"+
			"    lookup_id: %02xe2f3a4b5c6d7e8f9a0b1\n    issued_by: %s\n    status: active\n", i, i, i, walkPubkey)
	}
	return b.String()
}

const walkVaultEmpty = "schema_version: \"1\"\n"

// walker drives one rootModel and records every dumped screen.
type walker struct {
	t     *testing.T
	out   string
	paths *config.Paths
	bin   string
	m     *rootModel
	trail []string
	n     int
	keyN  int
	flow  string // current flow: every dump gets a flow:<name> tag
	seen  map[string]bool
	index strings.Builder
	shots []walkShot          // for the connectivity invariant
	at    map[string]walkShot // user keys → screen recorded there
}

type walkShot struct{ slug, title, keys string }

// userKeys drops what the lab auto-plays (quoted typed text, direct:*
// messages) and keeps the keys a user presses.
func userKeys(trail []string) string {
	var ks []string
	for _, k := range trail {
		if strings.HasPrefix(k, "direct:") || (len(k) > 1 && k[0] == '"') {
			continue
		}
		ks = append(ks, k)
	}
	return strings.Join(ks, "\x00")
}

// reset starts a fresh root model at launch (state comes from the fixture HOME).
func (w *walker) reset() { w.m = newRootModel(); w.trail = nil }

// keys sends key presses. Before each press, if the current state's
// user-key path has no recorded screen yet, it is dumped first (named
// after its predecessor + the key that reached it), so every screen is
// one key away from another — the lab navigates by replaying paths.
func (w *walker) keys(ks ...string) {
	for _, k := range ks {
		w.fill()
		w.m.Update(walkKey(k)) // ponytail: Cmd dropped — never executed
		if len(k) > 1 && !walkSpecial[k] {
			k = strconv.Quote(k)
		}
		w.trail = append(w.trail, k)
	}
}

// line walks a main line: presses keys and records the end state too.
func (w *walker) line(ks ...string) { w.keys(ks...); w.fill() }

// text types s (any length) as one paste; the lab auto-plays it.
func (w *walker) text(s string) {
	w.fill()
	w.m.Update(walkKey(s))
	w.trail = append(w.trail, strconv.Quote(s))
}

// fill dumps the current state when no screen sits at its user-key path.
func (w *walker) fill() {
	uk := userKeys(w.trail)
	if uk == "" || w.at[uk].slug != "" {
		return
	}
	i := strings.LastIndex(uk, "\x00")
	pred, key := "", uk
	if i >= 0 {
		pred, key = uk[:i], uk[i+1:]
	}
	prev := w.at[pred]
	if prev.slug == "" {
		w.t.Fatalf("fill: no screen at predecessor %q", pred)
	}
	name := map[string]string{" ": "space", "A": "all"}[key]
	if name == "" {
		name = strings.ToLower(key)
	}
	slug, n := prev.slug+"-"+name, 1
	// down down down → base-down, base-down2, base-down3
	if j := strings.LastIndex(prev.slug, "-"+name); j >= 0 {
		if c, err := strconv.Atoi(prev.slug[j+len(name)+1:]); err == nil || j+len(name)+1 == len(prev.slug) {
			if err != nil {
				c = 1
			}
			slug, n = prev.slug[:j]+"-"+name+strconv.Itoa(c+1), c+1
		}
	}
	for w.seen[slug] {
		n++
		slug = fmt.Sprintf("%s-%s%d", prev.slug, name, n)
	}
	title := prev.title + " · " + name
	if j := strings.LastIndex(prev.title, " · "+name); j >= 0 && n > 1 && strings.HasPrefix(slug, prev.slug[:strings.LastIndex(prev.slug, "-"+name)]) {
		title = fmt.Sprintf("%s · %s×%d", prev.title[:j], name, n)
	}
	w.dump(slug, title)
}

// send injects a view's own result message (what the dropped Cmd would return).
func (w *walker) send(label string, msg tea.Msg) {
	w.m.Update(msg)
	w.trail = append(w.trail, "direct:"+label)
}

// load runs a list view's Init loader inline: fixture vault.yaml + one
// status RPC to the fake daemon.
func (w *walker) load() {
	l, ok := w.m.child.(interface{ load() tea.Msg })
	if !ok {
		w.t.Fatalf("child %T has no load()", w.m.child)
	}
	w.send("load", l.load())
}

func (w *walker) dump(slug, title string, tags ...string) {
	if w.seen[slug] {
		w.t.Fatalf("duplicate slug %q", slug)
	}
	w.seen[slug] = true
	w.n++
	if w.flow != "" {
		tags = append(tags, "flow:"+w.flow)
	}
	for _, tg := range tags {
		if tg == "key" {
			w.keyN++
		}
	}
	sh := walkShot{slug, title, userKeys(w.trail)}
	w.shots = append(w.shots, sh)
	if w.at[sh.keys].slug == "" {
		w.at[sh.keys] = sh
	}
	path := strings.Join(w.trail, " ")
	if path == "" {
		path = "(launch)"
	}
	for _, sz := range [][2]int{{80, 24}, {120, 40}} {
		w.m.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		name := fmt.Sprintf("%03d-%s-%dx%d.ans", w.n, slug, sz[0], sz[1])
		must(w.t, os.WriteFile(filepath.Join(w.out, name), []byte(w.m.View()), 0o644))
		fmt.Fprintf(&w.index, "%s\t%s\t%s\t%s\n", name, title, path, strings.Join(tags, " "))
	}
}

func (w *walker) writeVault(body string) {
	must(w.t, os.WriteFile(filepath.Join(w.paths.Vault, "vault.yaml"), []byte(body), 0o600))
}

func (w *walker) inviteFile() string {
	return filepath.Join(w.paths.Vault, "pending-admin-invites", "3f9a0c1d2e4b5a69.invite.json")
}

func TestWalkScreens(t *testing.T) {
	out := os.Getenv("DOP_TUI_WALK")
	if out == "" {
		t.Skip("set DOP_TUI_WALK=<outdir> to dump every TUI screen")
	}
	lipgloss.SetColorProfile(termenv.TrueColor)
	must(t, os.MkdirAll(out, 0o755))
	orig := clipboardCopy
	clipboardCopy = func(string) bool { return true } // keep the real clipboard untouched
	t.Cleanup(func() { clipboardCopy = orig })

	// ponytail: fixture HOME lives in /tmp, not under outdir — the unix
	// socket path ($HOME/Library/Application Support/dop/admin.sock) blows
	// past the 104-byte sun_path limit under long outdirs. Removed on exit.
	home, err := os.MkdirTemp("/tmp", "dopwalk")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config")) // linux
	// Stub PATH: doctor's LookPath finds sops/git, pbcopy/xclip are absent
	// so copyToClipboard (called from View!) can't spawn anything.
	bin := filepath.Join(home, "bin")
	must(t, os.MkdirAll(bin, 0o755))
	for _, b := range []string{"sops", "git"} {
		must(t, os.WriteFile(filepath.Join(bin, b), nil, 0o755))
	}
	t.Setenv("PATH", bin)

	paths, err := config.Resolve()
	must(t, err)
	must(t, os.MkdirAll(paths.KeysDir, 0o700))

	w := &walker{t: t, out: out, paths: paths, bin: bin, seen: map[string]bool{}, at: map[string]walkShot{}}

	// The walk reads like a script: each flow starts from launch (reset)
	// and reaches its screens the way a user does.
	walkSetup(w) // no admin key, no vault, no daemon
	walkLogin(w) // key on disk → login → daemon up → attach vault
	walkMenu(w)  // full admin: unlocked + vault
	walkIntegrationAdd(w)
	walkGrantAdd(w)
	walkIssue(w)
	walkInvites(w)
	walkIntegrations(w)
	walkGrants(w)
	walkBearers(w)
	walkTeam(w)
	walkRemove(w)
	walkVaultOps(w)
	walkMore(w)
	walkEdge(w)
	walkPending(w) // last: the claim banner sticks to every later menu

	must(t, os.WriteFile(filepath.Join(out, "index.txt"), []byte(w.index.String()), 0o644))
	for _, l := range strings.Split(strings.TrimSpace(w.index.String()), "\n") {
		if name := strings.Split(l, "\t")[0]; strings.Contains(name, "80x24") {
			b, err := os.ReadFile(filepath.Join(out, name))
			must(t, err)
			checkScreen(t, name, string(b))
		}
	}

	// Sanity: colour forced, enough screens.
	b, err := os.ReadFile(filepath.Join(out, "001-menu-fresh-80x24.ans"))
	must(t, err)
	if !strings.Contains(string(b), "\x1b[") {
		t.Errorf("dumps carry no ANSI escapes — colour profile not forced")
	}
	if w.n < 100 {
		t.Errorf("%d screens dumped, want >= 100", w.n)
	}
	// Connectivity: the lab navigates by replaying key paths, so every
	// screen must be another screen's user keys + exactly one key (or a
	// launch screen with no user keys).
	have := map[string]bool{}
	for _, sh := range w.shots {
		have[sh.keys] = true
	}
	for _, sh := range w.shots {
		if sh.keys == "" {
			continue
		}
		pred := ""
		if i := strings.LastIndex(sh.keys, "\x00"); i >= 0 {
			pred = sh.keys[:i]
		}
		if !have[pred] {
			t.Errorf("unconnected %s: no screen at %q", sh.slug, strings.ReplaceAll(pred, "\x00", " "))
		}
	}
	t.Logf("dumped %d screens × 2 sizes (%d key) to %s", w.n, w.keyN, out)
}

// ── setup: fresh install (no admin key, no vault, no daemon) ──
func walkSetup(w *walker) {
	w.flow = "setup"
	w.reset()
	w.dump("menu-fresh", "Menu · fresh install · cursor on Setup admin", "key")
	for _, r := range []string{"Attach vault", "Join existing vault", "Doctor", "Uninstall", "Quit"} {
		w.keys("down")
		w.dump("menu-fresh-"+strings.ToLower(strings.Fields(r)[0]), "Menu · fresh install · cursor on "+r)
	}

	// Setup admin: 4 passphrase steps, review, running, harness
	w.reset()
	w.keys("enter")
	w.dump("setup-admin-empty", "Setup admin · 1 of 4 · admin passphrase empty")
	w.keys("?")
	w.dump("setup-admin-help", "Setup admin · expanded help")
	w.reset()
	w.keys("enter", "enter")
	w.dump("setup-admin-required", "Setup admin · empty passphrase refused", "edge")
	w.keys("hunter2", "enter")
	w.dump("setup-admin-too-short", "Setup admin · admin passphrase too short", "edge")
	w.text("2")
	w.dump("setup-admin-pass", "Setup admin · admin passphrase typed (masked)")
	w.keys("enter")
	w.dump("setup-admin-confirm", "Setup admin · 2 of 4 · confirm admin passphrase")
	w.keys("hunter2x", "enter")
	w.dump("setup-admin-mismatch", "Setup admin · confirmation mismatch", "key", "edge")
	w.keys("hunter22", "enter")
	w.dump("setup-admin-approval", "Setup admin · 3 of 4 · approval passphrase")
	w.keys("battery", "enter")
	w.dump("setup-admin-approval-short", "Setup admin · approval passphrase too short", "edge")
	w.keys("-staple", "enter")
	w.dump("setup-admin-approval-confirm", "Setup admin · 4 of 4 · confirm approval passphrase")
	w.keys("battery-staple")
	w.dump("setup-admin-filled", "Setup admin · last step filled")
	w.keys("enter")
	w.dump("setup-admin-review", "Setup admin · review", "key")
	w.keys("enter")
	w.dump("setup-admin-running", "Setup admin · generating keys")
	w.send("setupInitDone", setupInitDone{pass: "hunter22"})
	w.dump("setup-admin-login", "Setup admin · signing in")
	w.send("setupLoginDone", setupLoginDone{})
	w.dump("setup-admin-harness", "Setup admin · harness picker", "key")
	w.keys("down")
	w.dump("setup-admin-harness-codex", "Setup admin · harness picker · cursor on Codex")
	w.keys("enter")
	w.dump("setup-admin-done", "Setup admin · done → menu flash")

	w.reset()
	w.keys("enter", "hunter22", "enter", "hunter22", "enter", "battery-staple", "enter", "battery-staple", "enter", "enter")
	w.send("setupInitDone", setupInitDone{err: "admin key already exists at ~/Library/Application Support/dop/keys/admin.age.enc"})
	w.dump("setup-admin-init-failed", "Setup admin · init failed (review + error)", "edge")

	// Attach vault (agent install): single step
	w.reset()
	w.keys("down", "enter")
	w.dump("attach-agent-empty", "Attach vault · agent install · empty")
	w.keys("enter")
	w.dump("attach-agent-required", "Attach vault · URL required", "edge")
	w.keys("git@github.com:acme/dop-vault.git")
	w.dump("attach-agent-typed", "Attach vault · URL typed")
	w.keys("enter")
	w.dump("attach-agent-cloning", "Attach vault · cloning")
	w.send("attachResultMsg", attachResultMsg{err: "git clone: repository 'acme/dop-vault' not found"})
	w.dump("attach-agent-error", "Attach vault · clone failed", "edge")
	w.reset()
	w.keys("down", "enter", "git@github.com:acme/dop-vault.git", "enter")
	w.send("attachResultMsg", attachResultMsg{})
	w.dump("attach-agent-done", "Attach vault · done → menu flash")

	// Join existing vault
	w.reset()
	w.keys("down", "down", "enter")
	w.dump("join-url-empty", "Join vault · 1 of 5 · URL empty")
	w.keys("enter")
	w.dump("join-url-required", "Join vault · URL required", "edge")
	w.keys("git@github.com:acme/dop-vault.git", "enter", "AB-CD-EF")
	w.dump("join-pin", "Join vault · PIN typed")
	w.keys("enter")
	w.dump("join-identity-separate", "Join vault · identity · separate", "key")
	w.keys("down")
	w.dump("join-identity-shared", "Join vault · identity · same identity")
	w.keys("enter", "hunter22")
	w.dump("join-shared-pass", "Join vault · inviting machine's passphrase")
	w.keys("enter")
	w.dump("join-review", "Join vault · review")
	w.keys("enter")
	w.send("inviteLine", inviteLine{line: "… running: dop admin join"})
	w.send("inviteLine", inviteLine{line: "fetching invite 3f9a0c1d…"})
	w.dump("join-running", "Join vault · running")
	w.send("inviteDone", inviteDone{rc: 0})
	w.dump("join-harness", "Join vault · harness picker")
	w.keys("enter")
	w.dump("join-done", "Join vault · done → menu flash")

	w.reset()
	w.keys("down", "down", "enter", "git@github.com:acme/dop-vault.git", "enter", "AB-CD-EF", "enter", "enter")
	w.dump("join-new-admin", "Join vault · separate identity · new admin passphrase")
	w.keys("hunter2", "enter")
	w.dump("join-new-admin-short", "Join vault · new admin passphrase too short", "edge")
	w.text("2")
	w.keys("enter", "battery-staple")
	w.dump("join-new-approval", "Join vault · new approval passphrase typed")
	w.keys("enter", "enter")
	w.send("inviteLine", inviteLine{line: "error: invite 3f9a0c1d not found (expired or cancelled)"})
	w.send("inviteDone", inviteDone{rc: 1, err: "exit status 1"})
	w.dump("join-failed", "Join vault · failed (review + error)", "edge")
	w.keys("?")
	w.dump("join-failed-output", "Join vault · failed · last output behind ?", "edge")

	// Doctor, Uninstall
	w.reset()
	w.keys("down", "down", "down", "enter")
	w.dump("doctor-fresh", "Doctor · fresh install")
	w.reset()
	w.keys("down", "down", "down", "down", "enter")
	w.dump("uninstall-confirm", "Uninstall · confirm (fresh install)", "key")
	w.keys("uninstall", "enter")
	w.dump("uninstall-wrong-word", "Uninstall · lowercase confirm rejected", "edge")
	w.reset()
	w.keys("down", "down", "down", "down", "enter", "UNINSTALL", "enter")
	w.dump("uninstall-wiping", "Uninstall · wiping")
	w.send("resetDone", resetDone{rc: 1, err: "rm: ~/Library/Application Support/dop: Operation not permitted"})
	w.dump("uninstall-failed", "Uninstall · failed (confirm + error)", "edge")
	w.reset()
	w.keys("down", "down", "down", "down", "enter", "UNINSTALL", "enter")
	w.send("resetDone", resetDone{rc: 0})
	w.dump("uninstall-done", "Uninstall · done")
}

// ── login: admin key on disk, no session → unlock → attach vault ──
func walkLogin(w *walker) {
	w.flow = "login"
	must(w.t, os.WriteFile(filepath.Join(w.paths.KeysDir, "admin.age.enc"), []byte("walk"), 0o600))
	w.reset()
	w.dump("menu-locked", "Menu · admin locked")
	w.keys("enter", "s3cret!")
	w.dump("login-typing", "Login · passphrase typed")
	w.keys("enter")
	w.dump("login-unlocking", "Login · unlocking")
	w.send("loginResultMsg", loginResultMsg{err: "wrong passphrase (2 attempts left)"})
	w.dump("login-error", "Login · wrong passphrase", "edge")
	w.keys("correct horse", "enter")
	walkDaemon(w.t, admin.SockPath(w.paths)) // the session daemon the login subprocess would start
	w.send("loginResultMsg", loginResultMsg{})
	w.dump("menu-novault", "Menu · unlocked, no vault (login flash)")

	w.flow = "setup"
	w.keys("enter")
	w.dump("attach-admin-empty", "Attach vault · admin install · empty")
	w.keys("git@github.com:acme/dop-vault.git", "enter")
	// what `dop init --vault` leaves behind
	must(w.t, os.MkdirAll(filepath.Join(w.paths.Vault, "pending-admin-invites"), 0o755))
	w.writeVault(walkVault)
	must(w.t, os.WriteFile(w.inviteFile(), []byte(walkInvite), 0o644))
	w.send("attachResultMsg", attachResultMsg{})
	w.dump("attach-admin-done", "Attach vault · done → admin menu flash")
}

// ── admin top level ──
func walkMenu(w *walker) {
	w.flow = ""
	w.reset()
	w.dump("menu-admin", "Menu · admin top level", "key")
	w.keys("?")
	w.dump("menu-admin-help", "Menu · admin top level · expanded help")
	w.reset()
	w.keys("down")
	w.dump("menu-admin-cursor", "Menu · admin top level · cursor on Issue")
}

// esc presses esc and records where it lands (<screen>-esc): every
// inner mode goes back exactly one level.
func (w *walker) esc() { w.keys("esc"); w.fill() }

// ── integration-add ── (pick, then Integration › Credential › Grant dense forms, review)
func walkIntegrationAdd(w *walker) {
	w.flow = "integration-add"
	w.reset()
	w.keys("1")
	w.dump("menu-add", "Menu · Add group")
	w.keys("1")
	w.dump("integration-add-pick", "Add integration · new or existing", "key")
	w.keys("?")
	w.dump("integration-add-help", "Add integration · expanded help")
	w.esc()
	w.esc()
	w.reset()
	w.keys("1", "1", "enter")
	w.dump("integration-add-integ-empty", "Add integration · 1 of 3 · integration, empty", "key")
	w.esc()
	w.reset()
	w.keys("1", "1", "enter", "down", "down", "down", "down", "down")
	w.dump("integration-add-integ-next", "Add integration · cursor on Next")
	w.keys("enter")
	w.dump("integration-add-name-required", "Add integration · name required", "edge")
	w.keys("enter")
	w.dump("integration-add-name-open", "Add integration · name row open")
	w.keys("Notion Mirror")
	w.dump("integration-add-name", "Add integration · name typed (saved-as hint)")
	w.esc()
	toKind := func() { w.reset(); w.keys("1", "1", "enter", "enter", "Notion Mirror", "enter") }
	toKind()
	w.dump("integration-add-name-done", "Add integration · name set, cursor on kind")
	w.keys("enter")
	w.dump("integration-add-kind", "Add integration · kind picker open in place")
	w.esc()
	for i, kind := range []string{"cli", "mcp", "other"} {
		toKind()
		w.keys("enter")
		for j := 0; j <= i; j++ {
			w.keys("down")
		}
		w.dump("integration-add-kind-"+kind, "Add integration · kind picker · "+kind)
		w.keys("enter")
		w.dump("integration-add-rows-"+kind, "Add integration · rows for kind="+kind)
	}
	toKind()
	w.keys("enter", "down", "down", "enter", "enter", "Mirror over MCP", "enter", "enter", "https://mcp.example.com/sse", "enter")
	w.dump("integration-add-scan-row-mcp", "Add integration · mcp · cursor on scan")
	toKind()
	w.keys("enter", "enter", "enter", "Read-only mirror of the docs space", "enter", "enter", "https://api.notion.com/v1", "enter")
	w.dump("integration-add-scan-row", "Add integration · cursor on scan")
	w.keys("enter")
	w.dump("integration-add-scan", "Add integration · scan picker open")
	w.keys("down", "enter")
	w.dump("integration-add-integ-filled", "Add integration · integration filled, cursor on Next", "key")
	w.keys("enter")
	w.dump("integration-add-cred", "Add integration · 2 of 3 · credential, name prefilled", "key")
	w.esc()
	toCred := func() {
		toKind()
		w.keys("enter", "enter", "enter", "Read-only mirror of the docs space", "enter", "enter", "https://api.notion.com/v1", "enter", "enter", "down", "enter", "enter")
	}
	toCred()
	w.keys("down", "down", "down", "down", "enter")
	w.dump("integration-add-value-required", "Add integration · credential value required", "edge")
	w.keys("enter", "sk_live_51HxWalkFixture")
	w.dump("integration-add-value", "Add integration · credential value (masked)")
	w.keys("enter")
	w.dump("integration-add-scope-row", "Add integration · cursor on scope note")
	w.keys("enter")
	w.dump("integration-add-scope", "Add integration · scope picker open")
	w.keys("down", "down", "down", "enter")
	w.dump("integration-add-scope-custom-empty", "Add integration · custom scope note open")
	w.keys("read-only on /docs")
	w.dump("integration-add-scope-custom", "Add integration · custom scope typed")
	w.keys("enter")
	w.dump("integration-add-protect-row", "Add integration · cursor on protection")
	w.keys("enter")
	w.dump("integration-add-protect", "Add integration · protection picker open")
	w.keys("down", "enter")
	w.dump("integration-add-pass-row", "Add integration · passphrase row appears")
	w.keys("enter", "approve-me-please", "enter")
	w.dump("integration-add-cred-filled", "Add integration · credential filled, cursor on Next")
	w.keys("tab")
	w.dump("integration-add-advanced", "Add integration · Advanced tab (api)", "key")
	w.keys("enter", "https://api.notion.com", "enter", "enter", "docs,wiki", "enter", "enter", "bearer-header", "enter")
	w.dump("integration-add-advanced-filled", "Add integration · Advanced filled")
	w.keys("tab")
	w.dump("integration-add-normal", "Add integration · back on Normal")
	w.keys("down", "down", "down", "down", "down", "enter")
	w.dump("integration-add-grant", "Add integration · 3 of 3 · grant prefilled", "key")
	w.esc()
	toGrant := func() {
		toCred()
		w.keys("down", "enter", "sk_live_51HxWalkFixture", "enter", "enter", "enter", "enter", "enter", "enter")
	}
	toGrant()
	w.dump("integration-add-grant-readonly", "Add integration · grant id from the read-only scope")
	w.keys("enter", "ctrl+u", "notion-read", "enter")
	w.dump("integration-add-grant-id", "Add integration · grant id typed, cursor on env prefix")
	w.keys("down", "down", "down", "enter")
	w.dump("integration-add-grant-taken", "Add integration · grant id already exists", "edge")
	w.keys("enter", "ctrl+u", "notion-mirror.read-only", "enter", "down", "down", "down", "enter")
	w.dump("integration-add-review", "Add integration · review", "key")
	w.esc()
	toReview := func() { toGrant(); w.keys("down", "down", "down", "down", "enter") }
	toReview()
	w.keys("enter")
	w.dump("integration-add-saving", "Add integration · saving")
	w.send("integrationAddedMsg", integrationAddedMsg{err: "integration add: vault push rejected (non-fast-forward)"})
	w.dump("integration-add-error", "Add integration · save failed, nothing saved", "edge")
	w.keys("enter")
	w.send("integrationAddedMsg", integrationAddedMsg{integSaved: true})
	w.dump("integration-add-saving-grant", "Add integration · saving the grant (second call)")
	w.send("integrationAddedMsg", integrationAddedMsg{err: "grant add: vault push rejected (non-fast-forward)", integSaved: true})
	w.dump("integration-add-grant-error", "Add integration · grant failed, integration saved", "edge")
	w.keys("enter")
	w.send("integrationAddedMsg", integrationAddedMsg{})
	w.dump("integration-add-done", "Add integration · saved", "key")
	w.keys("enter")
	w.dump("integration-add-menu-flash", "Menu · flash after integration save")
	// session locked at save time: the review stays, the unlock opens
	// (its Cmd is dropped, so no dialog); cancelling it lands back there.
	toReview()
	walkLocked.Store(true)
	w.keys("enter")
	walkLocked.Store(false)
	w.dump("integration-add-save-locked", "Add integration · session locked at save, unlock prompt opening", "edge")
	w.send("guiUnlockResultMsg", guiUnlockResultMsg{success: false, stderr: "cancelled"})
	w.dump("integration-add-unlock-cancelled", "Add integration · unlock cancelled, back on the review", "edge")
	// existing integration: starts on the credential, step 1 shown done
	w.reset()
	w.keys("1", "1", "down", "down", "down", "down")
	w.dump("integration-add-pick-existing", "Add integration · cursor on notion")
	w.keys("enter")
	w.dump("integration-add-existing", "Add integration · credential on notion (no Advanced)")
	w.esc()
	w.reset()
	w.keys("1", "1", "enter", "enter", "notion", "enter", "down", "down", "down", "down", "enter")
	w.dump("integration-add-name-taken", "Add integration · notion already exists", "edge")
	// main line: every default (api, scan no, read-only, default protection)
	w.reset()
	w.keys("1", "1", "enter", "enter")
	w.text("Team docs mirror")
	w.keys("enter", "enter", "enter", "down", "enter")
	w.text("https://api.notion.com/v1")
	w.keys("enter", "down", "enter", "down", "enter")
	w.text("sk_live_51HxWalkFixture")
	w.line("enter", "down", "down", "enter", "down", "down", "down", "down", "enter", "enter")
}

// ── grant-add ── (one dense form, review)
func walkGrantAdd(w *walker) {
	w.flow = "grant-add"
	w.reset()
	w.keys("1", "2")
	w.dump("grant-add-form", "Add grant · prefilled from the first integration", "key")
	w.keys("?")
	w.dump("grant-add-help", "Add grant · expanded help")
	w.esc()
	w.esc()
	w.reset()
	w.keys("1", "2", "down")
	w.dump("grant-add-integ-row", "Add grant · cursor on integration")
	w.keys("enter")
	w.dump("grant-add-integration", "Add grant · integration picker open")
	w.esc()
	w.keys("enter", "down", "down", "down", "enter")
	w.dump("grant-add-notion", "Add grant · notion picked, id and env prefix follow")
	w.keys("enter")
	w.dump("grant-add-token", "Add grant · credential picker open (notion only)")
	w.keys("down", "enter")
	w.dump("grant-add-env", "Add grant · credential notion-write, cursor on env prefix")
	w.keys("down", "enter", "docs,wiki", "enter", "enter", "ro", "enter")
	w.dump("grant-add-filled", "Add grant · filled, cursor on Review")
	w.keys("enter")
	w.dump("grant-add-review", "Add grant · review", "key")
	w.esc()
	toReview := func() {
		w.reset()
		w.keys("1", "2", "down", "enter", "down", "down", "down", "enter", "enter", "down", "enter", "down", "down", "down", "enter")
	}
	toReview()
	w.keys("enter")
	w.dump("grant-add-saving", "Add grant · saving")
	w.send("grantAddedMsg", grantAddedMsg{err: "grant add: vault push rejected (non-fast-forward)"})
	w.dump("grant-add-error", "Add grant · save failed (review + error)", "edge")
	w.keys("enter")
	w.send("grantAddedMsg", grantAddedMsg{})
	w.dump("grant-add-done", "Add grant · saved")
	w.keys("enter")
	w.dump("grant-add-menu-flash", "Menu · flash after grant save")
	w.reset()
	w.keys("1", "2", "enter", "ctrl+u", "github", "enter", "down", "down", "down", "down", "down", "enter")
	w.dump("grant-add-id-taken", "Add grant · grant id already exists", "edge")
	// main line: first integration, first credential, defaults
	w.reset()
	w.keys("1", "2")
	w.line("down", "down", "down", "down", "down", "down", "enter", "enter")
}

// ── issue ── (wizard: enter next, esc / shift+tab prev, space toggle, ctrl+a all, n none; then review)
func walkIssue(w *walker) {
	w.flow = "issue"
	w.reset()
	w.keys("2")
	w.dump("issue-subject-empty", "Issue · 1 of 4 · subject empty")
	w.keys("claude-code-laptop")
	w.dump("issue-subject", "Issue · subject typed")
	w.keys("enter")
	w.dump("issue-grants", "Issue · grant picker · none selected", "key")
	w.esc()
	w.keys("enter", "enter")
	w.dump("issue-grants-required", "Issue · select at least one grant", "edge")
	w.keys(" ")
	w.dump("issue-grants-one", "Issue · one grant selected")
	w.keys("ctrl+a")
	w.dump("issue-grants-all", "Issue · ctrl+a selects all (env prefix collision)", "key", "edge")
	w.keys("enter")
	w.dump("issue-grants-collision", "Issue · collision blocks enter", "edge")
	w.keys("n")
	w.dump("issue-grants-none", "Issue · n clears the selection")
	w.keys(" ", "down", "down", "down", " ")
	w.dump("issue-grants-two", "Issue · two grants selected")
	w.keys("enter")
	w.dump("issue-expiry", "Issue · expiry presets", "key")
	w.esc()
	w.keys("enter", "down", "down", "down", "down", "down")
	w.dump("issue-expiry-custom-cursor", "Issue · expiry · cursor on custom…")
	w.keys("enter")
	w.dump("issue-expiry-custom", "Issue · custom expiry input")
	w.keys("10d")
	w.dump("issue-expiry-custom-typed", "Issue · custom expiry typed")
	w.keys("enter")
	w.dump("issue-portable", "Issue · portable · no")
	w.keys("down")
	w.dump("issue-portable-yes", "Issue · portable · yes")
	w.esc()

	toPortable := func() {
		w.reset()
		w.keys("2", "claude-code-laptop", "enter", " ", "down", "down", "down", " ", "enter",
			"down", "down", "down", "down", "down", "enter", "10d", "enter")
	}
	toPortable()
	w.keys("enter")
	w.dump("issue-confirm", "Issue · review", "key")
	w.keys("esc")
	w.dump("issue-review-back", "Issue · esc back from the review to portable")
	toPortable()
	w.keys("enter", "enter")
	w.dump("issue-issuing", "Issue · issuing (spinner)")
	w.send("issueResultMsg", issueResultMsg{bearer: "tok_7Hq2xWalkFixtureBearer0c1d2e3f", pin: "AB-CD-EF"})
	w.dump("issue-done", "Issue · bearer + PIN handoff", "key")
	w.keys("esc")
	w.dump("issue-done-esc-armed", "Issue · first esc arms leave (bearer still shown)", "edge")
	w.keys("esc")
	w.dump("issue-menu-flash", "Menu · flash after issue")
	toPortable()
	w.keys("down", "enter", "enter")
	w.send("issueResultMsg", issueResultMsg{bearer: "tok_9Kp4zWalkFixturePortable7a8b9c0d"})
	w.dump("issue-done-portable", "Issue · done, portable (bearer only)")
	toPortable()
	w.keys("enter", "enter")
	w.send("issueResultMsg", issueResultMsg{err: "vault push rejected (non-fast-forward)"})
	w.dump("issue-error", "Issue · issue failed (review + error)", "edge")

	w.reset()
	w.keys("2", "billing-agent", "enter", "down", "down", " ", "enter", "enter", "enter")
	w.dump("issue-protected-pass", "Issue · protected grant → approval passphrase")
	w.esc()
	w.reset()
	w.keys("2", "enter")
	w.dump("issue-subject-required", "Issue · subject required", "edge")
	w.esc()
	// main line: space on the first grant, then defaults (72h, not portable), review, issue
	w.reset()
	w.keys("2")
	w.text("claude-code-laptop")
	w.line("enter", " ", "enter", "enter", "enter", "enter")
}

// ── invite: device + team member ──
func walkInvites(w *walker) {
	w.flow = "invite"
	w.reset()
	w.keys("1", "3")
	w.dump("invite-device-empty", "Invite device · 1 of 3 · label empty")
	w.keys("enter")
	w.dump("invite-device-name-required", "Invite device · label required", "edge")
	w.keys("mac-mini")
	w.dump("invite-device-label", "Invite device · label typed")
	w.keys("enter")
	w.dump("invite-device-identity", "Invite device · identity · separate")
	w.esc()
	w.keys("enter", "down")
	w.dump("invite-device-identity-shared", "Invite device · identity · same (warning)")
	w.keys("enter")
	w.dump("invite-device-pass-empty", "Invite device · approval passphrase")
	w.keys("enter")
	w.dump("invite-device-pass-required", "Invite device · passphrase required", "edge")
	w.keys("approve-me-please")
	w.dump("invite-device-pass", "Invite device · passphrase typed")
	w.keys("enter")
	w.dump("invite-review", "Invite device · review", "key")
	w.keys("enter")
	w.dump("invite-running", "Invite · running")
	w.send("inviteLine", inviteLine{line: "  PIN:        AB-CD-EF   (valid 7d)"})
	w.send("inviteLine", inviteLine{line: "  invite_id:  3f9a0c1d2e4b5a69"})
	w.send("inviteLine", inviteLine{line: "  vault URL:  git@github.com:acme/dop-vault.git"})
	w.dump("invite-running-pin", "Invite · running, PIN captured", "key")
	w.send("inviteDone", inviteDone{rc: 0})
	w.dump("invite-waiting-shared", "Invite · staged, waiting (shared identity)")
	w.keys("esc")
	w.dump("invite-cancel-confirm", "Invite · cancel confirm")
	w.keys("y")
	w.dump("invite-cancelling", "Invite · cancelling")
	w.send("teamCancelDoneMsg", teamCancelDoneMsg{id: "3f9a0c1d2e4b5a69", err: "vault push rejected (non-fast-forward)"})
	w.dump("invite-cancel-failed", "Invite · cancel failed", "edge")
	w.keys("enter")
	w.dump("invite-done-flash", "Menu · invite left open (flash)")

	w.reset()
	w.keys("1", "3", "mac-mini", "enter", "enter", "approve-me-please", "enter", "enter")
	w.send("inviteLine", inviteLine{line: "  PIN:        AB-CD-EF   (valid 7d)"})
	w.send("inviteLine", inviteLine{line: "  invite_id:  3f9a0c1d2e4b5a69"})
	w.send("inviteLine", inviteLine{line: "  vault URL:  git@github.com:acme/dop-vault.git"})
	w.send("inviteDone", inviteDone{rc: 0})
	w.dump("invite-waiting", "Invite · staged, waiting (approve later)", "key")
	w.keys("esc", "y")
	w.send("teamCancelDoneMsg", teamCancelDoneMsg{id: "3f9a0c1d2e4b5a69"})
	w.dump("invite-cancelled-flash", "Menu · invite cancelled (flash)")

	w.reset()
	w.keys("1", "4")
	w.dump("invite-member-empty", "Invite team member · 1 of 2 · label empty")
	w.keys("alex", "enter")
	w.dump("invite-member-pass", "Invite team member · passphrase (no identity step)")
	w.keys("approve", "enter")
	w.dump("invite-member-review", "Invite team member · review")
	w.keys("enter")
	w.send("inviteLine", inviteLine{line: "error: vault push rejected (non-fast-forward)"})
	w.send("inviteDone", inviteDone{rc: 1, err: "exit status 1"})
	w.dump("invite-member-failed", "Invite team member · failed (review + error)", "edge")
	w.keys("?")
	w.dump("invite-member-failed-output", "Invite team member · failed · last output behind ?", "edge")
	// main line: separate identity → passphrase → review → running
	w.reset()
	w.keys("1", "3")
	w.text("mac-mini")
	w.keys("enter", "enter")
	w.text("approve-me-please")
	w.line("enter", "enter")
}

// ── integrations list ──
func walkIntegrations(w *walker) {
	w.flow = "integrations"
	w.reset()
	w.keys("3")
	w.dump("menu-list", "Menu · List group")
	w.keys("1")
	w.dump("integration-list-loading", "Integrations · loading")
	w.load()
	w.dump("integration-list", "Integrations · list (long name first)", "key", "edge")
	w.keys("?")
	w.dump("integration-list-help", "Integrations · expanded help")
	w.esc()
	w.esc()
	open := func() { w.reset(); w.keys("3", "1"); w.load() }
	open()
	w.keys("down", "down", "down", "enter")
	w.dump("integration-detail", "Integrations · notion · Info tab", "key")
	w.keys("tab")
	w.dump("integration-tokens", "Integrations · notion · Credentials tab")
	w.keys("tab")
	w.dump("integration-grants", "Integrations · notion · Grants tab")
	w.keys("enter")
	w.dump("integration-grant-detail", "Integrations · grant detail from the Grants tab")
	w.keys("esc")
	w.dump("integration-grant-back", "Integrations · back on the Grants tab")
	open()
	w.keys("down", "down", "enter", "tab")
	w.dump("integration-tokens-placeholder", "Integrations · linear · placeholder credential", "edge")
	w.esc()
	tok := func() { open(); w.keys("down", "down", "down", "enter", "tab", "enter") }
	tok()
	w.dump("integration-token-actions", "Integrations · credential actions")
	w.esc()
	w.keys("enter", "enter")
	w.dump("integration-token-scope", "Integrations · scope note picker")
	w.esc()
	w.keys("enter", "down", "down", "down", "enter")
	w.dump("integration-token-scope-custom", "Integrations · scope note custom (prefilled)")
	w.esc()
	w.keys("enter")
	w.keys(" on /docs")
	w.dump("integration-token-scope-typed", "Integrations · scope note custom typed")
	w.keys("enter")
	w.dump("integration-working", "Integrations · working")
	w.send("integActionMsg", integActionMsg{})
	w.dump("integration-scope-done", "Integrations · scope note saved")
	tok()
	w.keys("down", "enter")
	w.dump("integration-token-rotate", "Integrations · rotate value")
	w.esc()
	w.keys("enter", "enter")
	w.dump("integration-token-rotate-required", "Integrations · new value required", "edge")
	w.keys("sk_rotated_value_2026")
	w.dump("integration-token-rotate-typed", "Integrations · new value (masked)")
	w.keys("enter")
	w.send("integActionMsg", integActionMsg{err: "integration set-token: vault push rejected (non-fast-forward)"})
	w.dump("integration-action-error", "Integrations · rotate failed (error on the form)", "key", "edge")
	tok()
	w.keys("down", "down", "down", "enter")
	w.dump("integration-token-remove-confirm", "Integrations · remove credential confirm")
	w.esc()
	w.keys("enter", "y")
	w.send("integActionMsg", integActionMsg{})
	w.dump("integration-token-removed", "Integrations · credential removed")

	// n — rename credential: one input, enter saves
	tok()
	w.keys("down", "down", "enter")
	w.dump("integration-token-rename", "Integrations · rename credential · prefilled", "key")
	w.keys("enter")
	w.dump("integration-token-rename-same", "Integrations · rename credential · unchanged name", "edge")
	w.keys("ctrl+u", "notion-write", "enter")
	w.dump("integration-token-rename-taken", "Integrations · rename credential · name taken", "edge")
	w.keys("ctrl+u", "notion-ro")
	w.dump("integration-token-rename-typed", "Integrations · rename credential · new name typed")
	w.keys("enter")
	w.dump("integration-token-renaming", "Integrations · renaming credential")
	w.send("integActionMsg", integActionMsg{err: "integration rename-token: vault push rejected (non-fast-forward)"})
	w.dump("integration-token-rename-error", "Integrations · rename failed (error on the step)", "edge")
	w.keys("enter")
	w.send("integActionMsg", integActionMsg{})
	w.dump("integration-token-renamed", "Integrations · credential renamed")
	open()
	w.keys("down", "down", "down", "enter", "tab", "n")
	w.dump("integration-token-rename-key", "Integrations · n on the Credentials tab opens the rename")
	open()
	w.keys("enter", "tab", "n", "ctrl+u", "readonly-reporting", "enter")
	w.dump("integration-token-rename-pass", "Integrations · rename on a protected integration asks the passphrase", "edge")

	// e — edit integration: dense form, Normal / Advanced tabs, review
	open()
	w.keys("down", "down", "down", "e")
	w.dump("integration-edit", "Integrations · edit · form closed, cursor on name", "key")
	w.keys("?")
	w.dump("integration-edit-help", "Integrations · edit · expanded help")
	w.esc()
	w.keys("enter")
	w.dump("integration-edit-name", "Integrations · edit · name open")
	w.keys("ctrl+u", "notion-docs", "enter")
	w.dump("integration-edit-name-set", "Integrations · edit · renamed, cursor on kind")
	w.keys("enter")
	w.dump("integration-edit-kind", "Integrations · edit · kind picker open in place")
	w.keys("esc", "down", "enter")
	w.dump("integration-edit-desc", "Integrations · edit · description open")
	w.keys("esc", "down", "enter")
	w.dump("integration-edit-url", "Integrations · edit · base URL open")
	w.keys("esc", "down", "enter")
	w.dump("integration-edit-scan", "Integrations · edit · scan picker open")
	w.keys("esc", "down", "enter")
	w.dump("integration-edit-projects", "Integrations · edit · projects open")
	w.keys("ctrl+u", "docs,wiki", "enter", "enter")
	w.dump("integration-edit-tags", "Integrations · edit · tags open")
	w.keys("esc", "down", "enter")
	w.dump("integration-edit-protect", "Integrations · edit · protection picker open")
	w.keys("down", "enter")
	w.dump("integration-edit-pass-row", "Integrations · edit · passphrase row appears")
	w.keys("down")
	w.dump("integration-edit-review-row", "Integrations · edit · cursor on Review")
	w.keys("enter")
	w.dump("integration-edit-pass-required", "Integrations · edit · passphrase required", "edge")
	w.keys("enter", "approve-me-please", "enter")
	w.dump("integration-edit-filled", "Integrations · edit · filled, cursor on Review")
	w.keys("tab")
	w.dump("integration-edit-advanced", "Integrations · edit · Advanced tab (api)", "key")
	w.keys("enter")
	w.dump("integration-edit-advanced-open", "Integrations · edit · server root open")
	w.keys("https://api.notion.com", "enter", "tab")
	w.dump("integration-edit-normal", "Integrations · edit · back on Normal")
	w.keys("down", "down", "down", "down", "down", "down", "down", "down", "down", "enter")
	w.dump("integration-edit-review", "Integrations · edit · review of the changed rows", "key")
	w.keys("enter")
	w.dump("integration-edit-working", "Integrations · edit · saving")
	w.send("integActionMsg", integActionMsg{err: "integration add: vault push rejected (non-fast-forward)"})
	w.dump("integration-edit-error", "Integrations · edit · save failed (error on the review)", "edge")
	w.keys("enter")
	w.send("integActionMsg", integActionMsg{})
	w.dump("integration-edit-done", "Integrations · integration saved")
	w.keys("enter")
	w.dump("integration-edit-back", "Integrations · back on the Info tab")
	open()
	w.keys("down", "e", "tab")
	w.dump("integration-edit-advanced-cli", "Integrations · edit · Advanced tab (cli)")
	open()
	w.keys("down", "down", "down", "e", "down", "down", "down", "down", "down", "down", "down", "down")
	w.dump("integration-edit-unchanged", "Integrations · edit · untouched, cursor on Review")
	w.keys("enter")
	w.dump("integration-edit-no-changes", "Integrations · edit · review, no changes", "edge")
	w.keys("enter")
	w.dump("integration-edit-closed", "Integrations · no changes, back on the detail")
	open()
	w.keys("down", "down", "down", "e", "down", "enter", "down", "enter")
	w.dump("integration-edit-kind-changed", "Integrations · edit · kind api → cli clears the slot (command)", "edge")

	// r — remove confirm with cascade; a failure stays on the list
	open()
	w.keys("down", "down", "down", "r")
	w.dump("integration-remove-confirm", "Integrations · remove confirm (cascade grants)", "key")
	w.esc()
	w.keys("r", "y")
	w.dump("integration-remove-working", "Integrations · removing")
	w.send("integActionMsg", integActionMsg{err: "integration remove: vault push rejected (non-fast-forward)"})
	w.dump("integration-remove-error", "Integrations · remove failed (error on the list)", "edge")
	w.keys("r", "y")
	w.send("integActionMsg", integActionMsg{})
	w.dump("integration-remove-done", "Integrations · integration removed")
	open()
	w.keys("enter")
	w.dump("integration-detail-long", "Integrations · Info of protected long-name service", "edge")
	w.keys("down", "enter")
	w.dump("integration-detail-remove", "Integrations · remove confirm from the detail")
	w.esc()
	w.esc()
	// default picker choices: scope note keeps its preset, edit saves unchanged
	tok()
	w.line("enter", "enter")
	// a on the Credentials tab: the add form on this integration
	w.flow = "integration-add"
	open()
	w.keys("down", "down", "down", "enter", "tab", "a")
	w.dump("integration-add-credential", "Add integration · credential on notion from the Credentials tab", "key")
	w.esc()
	w.keys("a", "down", "enter", "secret_ntn_walk_7f3e", "enter", "down", "enter")
	w.dump("integration-add-credential-taken", "Add integration · notion already has credential notion", "edge")
	w.keys("enter", "ctrl+u", "notion-ci", "enter", "down", "down", "enter")
	w.dump("integration-add-credential-grant", "Add integration · grant for the new credential")
	w.keys("down", "down", "down", "down", "enter")
	w.dump("integration-add-credential-review", "Add integration · review (existing integration)")
	w.flow = "grant-add"
	open()
	w.keys("down", "down", "down", "enter", "tab", "tab", "a")
	w.dump("grant-add-from-tab", "Add grant · from the Grants tab, notion pre-filled", "key")
	w.esc()
	w.flow = "integrations"
}

// ── grants list ──
func walkGrants(w *walker) {
	w.flow = "grants"
	open := func() { w.reset(); w.keys("3", "2"); w.load() }
	open()
	w.dump("grant-list", "Grants · list (long id)", "edge")
	w.keys("?")
	w.dump("grant-list-help", "Grants · expanded help")
	w.esc()
	w.esc()
	open()
	w.keys("enter")
	w.dump("grant-detail", "Grants · detail + actions (protected)", "key")
	w.esc()
	edit := func() { open(); w.keys("down", "enter", "enter") }
	edit()
	w.dump("grant-edit", "Grants · edit · form closed, cursor on projects", "key")
	w.keys("enter")
	w.dump("grant-edit-projects", "Grants · edit · projects open")
	w.keys("ci-tools", "enter", "enter")
	w.dump("grant-edit-tags", "Grants · edit · tags open")
	w.keys("esc", "down", "enter")
	w.dump("grant-edit-env", "Grants · edit · env prefix open (default as placeholder)")
	w.keys("esc", "down", "enter")
	w.dump("grant-edit-protect", "Grants · edit · protection picker open")
	w.keys("down", "enter")
	w.dump("grant-edit-pass", "Grants · edit · passphrase row appears")
	w.keys("down", "enter")
	w.dump("grant-edit-pass-required", "Grants · edit · passphrase required", "edge")
	w.keys("enter", "approve-me-please", "enter")
	w.dump("grant-edit-filled", "Grants · edit · filled, cursor on Review")
	w.keys("enter")
	w.dump("grant-edit-review", "Grants · edit · review of the changed rows", "key")
	w.keys("enter")
	w.dump("grant-edit-saving", "Grants · edit · saving")
	w.send("grantActionMsg", grantActionMsg{kind: "edit", err: "grant add: protected grant needs --passphrase-stdin"})
	w.dump("grant-edit-error", "Grants · edit · save failed (error on the review)", "edge")
	w.keys("enter")
	w.send("grantActionMsg", grantActionMsg{kind: "edit"})
	w.dump("grant-edit-done", "Grants · grant saved")
	w.keys("enter")
	w.dump("grant-edit-back", "Grants · back on the grant detail")
	edit()
	w.keys("down", "down", "down", "down", "enter")
	w.dump("grant-edit-no-changes", "Grants · edit · review, no changes", "edge")
	w.keys("enter")
	w.dump("grant-edit-closed", "Grants · no changes, back on the detail")
	// n — rename: one input prefilled, enter saves
	rename := func() { open(); w.keys("down", "down", "down", "enter", "n") }
	rename()
	w.dump("grant-rename", "Grants · rename · prefilled", "key")
	w.keys("enter")
	w.dump("grant-rename-same", "Grants · rename · unchanged id", "edge")
	w.keys("ctrl+u", "github", "enter")
	w.dump("grant-rename-taken", "Grants · rename · id taken", "edge")
	w.keys("ctrl+u", "notion-docs-read")
	w.dump("grant-rename-typed", "Grants · rename · new id typed")
	w.keys("enter")
	w.dump("grant-renaming", "Grants · renaming")
	w.send("grantActionMsg", grantActionMsg{kind: "rename", err: "grant rename: vault push rejected (non-fast-forward)"})
	w.dump("grant-rename-error", "Grants · rename failed (error on the step)", "edge")
	w.keys("enter")
	w.send("grantActionMsg", grantActionMsg{kind: "rename"})
	w.dump("grant-renamed", "Grants · grant renamed")
	open()
	w.keys("enter", "n", "ctrl+u", "acme-billing-ro", "enter")
	w.dump("grant-rename-pass", "Grants · rename on a protected grant asks the passphrase", "edge")
	open()
	w.keys("down", "down", "down", "down", "enter", "down", "down", "enter")
	w.dump("grant-remove-confirm", "Grants · remove confirm")
	w.esc()
	w.keys("enter", "y")
	w.dump("grant-remove-saving", "Grants · removing")
	w.send("grantActionMsg", grantActionMsg{kind: "remove", err: "grant remove: vault push rejected"})
	w.dump("grant-remove-error", "Grants · remove failed (error on the detail)", "edge")
	w.keys("enter", "y")
	w.send("grantActionMsg", grantActionMsg{kind: "remove"})
	w.dump("grant-remove-done", "Grants · grant removed")
	// main line through the edit form: one changed row, saved
	edit()
	w.line("enter", "ci-tools", "enter", "down", "down", "down", "enter", "enter")
}

// ── bearers list ──
func walkBearers(w *walker) {
	w.flow = "bearers"
	open := func() { w.reset(); w.keys("3", "3"); w.load() }
	open()
	w.dump("bearer-list", "Bearers · active", "key")
	w.keys("?")
	w.dump("bearer-list-help", "Bearers · expanded help")
	w.esc()
	w.esc()
	open()
	w.keys("enter")
	w.dump("bearer-detail", "Bearers · Info tab (PIN-bound, unclaimed)", "key")
	w.esc()
	act := func() { open(); w.keys("enter") }
	act()
	w.keys("enter")
	w.dump("bearer-reseal-running", "Bearers · reseal running", "edge")
	w.send("listActionMsg", listActionMsg{err: "token reseal: bearer is PIN-bound and unclaimed — nothing to reseal"})
	w.dump("bearer-reseal-error", "Bearers · reseal failed", "edge")
	act()
	w.keys("enter")
	w.send("listActionMsg", listActionMsg{flash: "resealed claude-code-laptop · env updated (gen 4)"})
	w.dump("bearer-reseal-done", "Bearers · env resealed")
	grants := func() { act(); w.keys("tab") }
	grants()
	w.dump("bearer-grants", "Bearers · Grants tab", "key")
	w.esc()
	grants()
	w.keys("a")
	w.dump("bearer-add-grant", "Bearers · add-grant picker (grouped)", "key")
	w.esc()
	w.keys("a", "down", " ")
	w.dump("bearer-add-grant-picked", "Bearers · protected grant picked")
	w.keys("enter")
	w.dump("bearer-add-grant-pass-empty", "Bearers · approval passphrase for protected grant")
	w.esc()
	w.keys("enter", "approve-me-please")
	w.dump("bearer-add-grant-pass", "Bearers · approval passphrase typed")
	w.keys("enter")
	w.dump("bearer-add-grant-running", "Bearers · add-grant running")
	w.send("listActionMsg", listActionMsg{flash: "acme-billing-reconciliation-readonly-reporting-grant-for-finance-agents"})
	w.dump("bearer-add-grant-done", "Bearers · grant added", "edge")
	grants()
	w.keys("down")
	w.dump("bearer-grants-cursor", "Bearers · Grants tab · cursor on notion-read")
	w.keys("r")
	w.dump("bearer-remove-grant-confirm", "Bearers · remove grant confirm", "key")
	w.esc()
	w.keys("r", "enter")
	w.dump("bearer-remove-grant-running", "Bearers · remove-grant running")
	w.send("listActionMsg", listActionMsg{err: "token remove-grant: bearer is not P-256 bound — revoke + reissue instead"})
	w.dump("bearer-remove-grant-error", "Bearers · remove-grant failed", "edge")
	act()
	w.keys("down", "enter")
	w.dump("bearer-repin", "Bearers · repin PIN validity picker", "key")
	w.keys("down", "enter")
	w.dump("bearer-repin-confirm", "Bearers · re-issue with a new PIN?", "key")
	w.keys("enter")
	w.dump("bearer-repin-running", "Bearers · re-issuing (repin)")
	w.send("issueResultMsg", issueResultMsg{err: "dop token repin: save vault: vault push rejected (non-fast-forward)"})
	w.dump("bearer-repin-error", "Bearers · repin failed", "edge")
	w.keys("enter")
	w.send("issueResultMsg", issueResultMsg{bearer: "tok_9Kp4mWalkFixtureRepinned1a2b3c4d", pin: "KM-PX-RT"})
	w.dump("bearer-repin-done", "Bearers · re-issued with a new PIN, shown once", "key")
	w.keys("esc")
	w.dump("bearer-repin-done-esc-armed", "Bearers · repin done · first esc arms leave", "edge")
	// finance-agent holds a protected grant: the approval passphrase.
	open()
	w.keys("down", "down", "enter", "down", "enter", "enter", "enter")
	w.dump("bearer-repin-pass", "Bearers · repin · passphrase (protected grant)")
	w.keys("approve-me-please", "enter")
	w.dump("bearer-repin-pass-running", "Bearers · re-issuing (repin, protected)")
	// Portable: remove the copy (claude-code-laptop has one).
	act()
	w.keys("down", "down", "enter")
	w.dump("bearer-portable-off-confirm", "Bearers · remove portable copy confirm", "key")
	w.keys("enter")
	w.dump("bearer-portable-off-pass", "Bearers · remove portable copy passphrase")
	w.keys("approve-me-please", "enter")
	w.dump("bearer-portable-off-running", "Bearers · removing portable copy")
	w.send("listActionMsg", listActionMsg{err: "dop token portable: approval passphrase incorrect"})
	w.dump("bearer-portable-off-error", "Bearers · remove portable copy failed", "edge")
	w.keys("approve-me-please", "enter")
	w.send("listActionMsg", listActionMsg{})
	w.dump("bearer-portable-off-done", "Bearers · portable copy removed")
	// Portable: make portable re-issues. codex-ci-runner is claimed: rotated in place.
	open()
	w.keys("down", "enter", "down", "enter")
	w.dump("bearer-portable-on-confirm", "Bearers · re-issue as portable · claimed", "key")
	w.keys("enter")
	w.dump("bearer-portable-on-running", "Bearers · re-issuing")
	w.send("issueResultMsg", issueResultMsg{err: "dop token portable: save vault: vault push rejected (non-fast-forward)"})
	w.dump("bearer-portable-on-error", "Bearers · re-issue failed", "edge")
	w.keys("enter")
	w.send("issueResultMsg", issueResultMsg{})
	prefs := LoadPrefs(w.paths)
	for _, h := range []string{userprefs.HarnessClaudeCode, userprefs.HarnessCodex} {
		p := prefs
		p.Harness = h
		must(w.t, SavePrefs(w.paths, p))
		w.dump("bearer-portable-on-done-"+h, "Bearers · bearer is portable · "+userprefs.HarnessLabel(h))
	}
	// finance-agent is unclaimed and holds a protected grant: passphrase,
	// then a new bearer + PIN shown once.
	open()
	w.keys("down", "down", "enter", "down", "down", "enter")
	w.dump("bearer-portable-on-unclaimed-confirm", "Bearers · re-issue as portable · unclaimed")
	w.keys("enter")
	w.dump("bearer-portable-on-pass", "Bearers · re-issue as portable · passphrase (protected grant)")
	w.keys("approve-me-please", "enter")
	w.send("issueResultMsg", issueResultMsg{bearer: "tok_3Rt8vWalkFixtureReissued5e6f7a8b", pin: "QR-ST-UV"})
	w.dump("bearer-portable-on-reissued", "Bearers · re-issued, bearer + PIN shown once", "key")
	w.keys("esc")
	w.dump("bearer-portable-on-reissued-esc-armed", "Bearers · re-issued · first esc arms leave", "edge")
	must(w.t, SavePrefs(w.paths, prefs))
	act()
	w.keys("down", "down", "down", "enter")
	w.dump("bearer-revoke-confirm", "Bearers · revoke confirm", "key")
	w.esc()
	w.keys("enter", "y")
	w.dump("bearer-revoke-running", "Bearers · revoking")
	w.send("listActionMsg", listActionMsg{})
	w.dump("bearer-revoke-done", "Bearers · revoked")

	open()
	w.keys("down", "enter")
	w.dump("bearer-detail-claimed", "Bearers · detail (claimed P-256, no repin)")
	open()
	w.keys("tab")
	w.dump("bearer-list-all", "Bearers · Revoked tab")
	w.keys("enter")
	w.dump("bearer-detail-revoked", "Bearers · detail (revoked, no actions)")
	w.keys("tab")
	w.dump("bearer-grants-revoked", "Bearers · Grants tab of a revoked bearer")
	// Prune on the Revoked tab: old-notion-agent was revoked > 30d ago.
	open()
	w.keys("tab", "x")
	w.dump("bearer-prune-confirm", "Bearers · prune confirm", "key")
	w.keys("enter")
	w.dump("bearer-prune-running", "Bearers · pruning")
	w.send("listActionMsg", listActionMsg{err: "dop token prune: save vault: vault push rejected (non-fast-forward)"})
	w.dump("bearer-prune-error", "Bearers · prune failed", "edge")
	w.keys("x", "enter")
	w.send("listActionMsg", listActionMsg{})
	w.dump("bearer-prune-done", "Bearers · pruned")
	// default picker choice: repin TTL 1h
	act()
	w.keys("down", "enter")
	w.line("enter", "enter")
}

// ── team ──
func walkTeam(w *walker) {
	w.flow = "team"
	open := func() { w.reset(); w.keys("3", "4"); w.load() }
	open()
	w.dump("team-members", "Team · members tab")
	w.keys("tab")
	w.dump("team-pending", "Team · pending tab", "key")
	w.keys("a")
	w.dump("team-approve-empty", "Team · approve passphrase")
	w.esc()
	w.keys("a", "enter")
	w.dump("team-approve-required", "Team · passphrase required", "edge")
	w.keys("approve-me-please")
	w.dump("team-approve-typed", "Team · passphrase typed")
	w.keys("enter")
	w.dump("team-approve-running", "Team · approving")
	w.send("teamApproveDoneMsg", teamApproveDoneMsg{id: "3f9a0c1d2e4b5a69", err: "no response from teammate yet: they have not run dop admin join"})
	w.dump("team-approve-failed", "Team · approve failed (back on the passphrase)", "edge")
	w.keys("enter")
	w.send("teamApproveDoneMsg", teamApproveDoneMsg{id: "3f9a0c1d2e4b5a69"})
	w.dump("team-approve-done", "Team · member approved")
	w.keys("enter")
	w.load()
	w.dump("team-approve-flash", "Team · approved (flash)")
	open()
	w.keys("tab", "d")
	w.dump("team-delete-confirm", "Team · delete pending invite confirm")
	w.esc()
	w.keys("d", "y")
	w.dump("team-delete-running", "Team · cancelling invite")
	w.send("teamCancelDoneMsg", teamCancelDoneMsg{id: "3f9a0c1d2e4b5a69"})
	w.load()
	w.dump("team-delete-done", "Team · invite cancelled (flash)")

	// Add → Team member by key
	w.reset()
	w.keys("1", "5")
	w.dump("team-add-name", "Add team member · 1 of 4 · name")
	w.esc()
	w.keys("5")
	w.keys("enter")
	w.dump("team-add-name-required", "Add team member · name required", "edge")
	w.keys("bob", "enter", "ssh-ed25519 AAAAC3Nza", "enter")
	w.dump("team-add-bad-pubkey", "Add team member · not an age recipient", "edge")
	w.reset()
	w.keys("1", "5", "bob", "enter", "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj", "enter", "enter", "Bob's MacBook")
	w.dump("team-add-filled", "Add team member · last step filled")
	w.keys("enter")
	w.dump("team-add-review", "Add team member · review")
	w.keys("enter")
	w.dump("team-add-running", "Add team member · adding")
	w.send("teamAddResultMsg", teamAddResultMsg{})
	w.dump("team-add-done", "Add team member · added")
	w.keys("x")
	w.dump("team-add-flash", "Menu · team member added (flash)")
}

// ── remove group ──
func walkRemove(w *walker) {
	w.flow = "remove"
	w.reset()
	w.keys("4")
	w.dump("menu-remove", "Menu · Remove group")
	w.keys("1")
	w.load()
	w.dump("revoke-pick", "Revoke bearer · pick")
	w.keys("enter")
	w.dump("revoke-confirm", "Revoke bearer · confirm")
	w.esc()
	w.keys("enter", "y")
	w.dump("revoke-running", "Revoke bearer · revoking")
	w.send("revokeResultMsg", revokeResultMsg{err: "revoke: vault push rejected"})
	w.dump("revoke-error", "Revoke bearer · failed", "edge")
	w.keys("y")
	w.send("revokeResultMsg", revokeResultMsg{})
	w.dump("revoke-done", "Done · done screen")
	w.keys("enter")
	w.dump("revoke-flash", "Menu · revoked (flash)")

	w.reset()
	w.keys("4", "2")
	w.load()
	w.dump("grant-remove-pick", "Remove grant · pick")
	w.keys("enter")
	w.dump("grant-remove-pick-confirm", "Remove grant · confirm")
	w.esc()
	w.keys("enter", "y")
	w.dump("grant-remove-pick-running", "Remove grant · removing")
	w.send("grantRemoveResultMsg", grantRemoveResultMsg{err: "grant remove: grant is protected — owner passphrase required"})
	w.dump("grant-remove-pick-error", "Remove grant · failed", "edge")
	w.keys("y")
	w.send("grantRemoveResultMsg", grantRemoveResultMsg{})
	w.dump("grant-remove-pick-done", "Done · done screen")
	w.keys("enter")
	w.dump("grant-remove-pick-flash", "Menu · grant removed (flash)")

	w.reset()
	w.keys("4", "3")
	w.load()
	w.dump("integration-remove-pick", "Remove credentials · pick service")
	w.keys("down", "enter")
	w.dump("integration-remove-tokens", "Remove credentials · pick credentials")
	w.esc()
	w.keys("enter", "enter")
	w.dump("integration-remove-required", "Remove credentials · select at least one", "edge")
	w.keys(" ")
	w.dump("integration-remove-selected", "Remove credentials · one selected")
	w.keys("enter")
	w.dump("integration-remove-preview", "Remove credentials · cascade preview", "key")
	w.esc()
	w.keys("enter", "y")
	w.dump("integration-remove-pick-running", "Remove credentials · removing")
	w.send("integrationRemoveResultMsg", integrationRemoveResultMsg{err: "integration remove: vault push rejected"})
	w.dump("integration-remove-pick-error", "Remove credentials · failed", "edge")
	w.keys("y")
	w.send("integrationRemoveResultMsg", integrationRemoveResultMsg{})
	w.dump("integration-remove-pick-done", "Done · done screen")
	w.keys("enter")
	w.dump("integration-remove-pick-flash", "Menu · credentials removed (flash)")

	w.reset()
	w.keys("4", "4")
	w.load()
	w.dump("team-remove-pick", "Remove team member · pick")
	w.keys("down", "enter")
	w.dump("team-remove-confirm", "Remove team member · rotation checklist")
	w.esc()
	w.keys("enter", "y")
	w.dump("team-remove-running", "Remove team member · removing")
	w.send("teamRemoveResultMsg", teamRemoveResultMsg{err: "team remove: cannot remove the last admin with a live session"})
	w.dump("team-remove-error", "Remove team member · failed", "edge")
	w.keys("y")
	w.send("teamRemoveResultMsg", teamRemoveResultMsg{})
	w.dump("team-remove-done", "Done · done screen")
	w.keys("enter")
	w.dump("team-remove-flash", "Menu · team member removed (flash)")
}

// ── vault group ──
func walkVaultOps(w *walker) {
	w.flow = "vault"
	w.reset()
	w.keys("5")
	w.dump("menu-vault", "Menu · Vault group")
	w.keys("1")
	w.dump("vault-status", "Vault · session status")
	for _, op := range []struct{ key, name string }{{"2", "pull"}, {"3", "push"}} {
		w.reset()
		w.keys("5", op.key)
		w.dump("vault-"+op.name+"-running", "Vault · "+op.name+" running")
		w.send("syncResultMsg", syncResultMsg{out: "Already up to date.\nvault: 5 integrations · 5 grants · 3 capabilities\n"})
		w.dump("vault-"+op.name+"-done", "Vault · "+op.name+" done")
		w.keys("x")
		w.dump("vault-"+op.name+"-flash", "Menu · "+op.name+" succeeded (flash)")
		w.reset()
		w.keys("5", op.key)
		w.send("syncResultMsg", syncResultMsg{err: "! [rejected] main -> main (fetch first)\nerror: failed to " + op.name + " some refs"})
		w.dump("vault-"+op.name+"-error", "Vault · "+op.name+" failed", "edge")
	}
	w.reset()
	w.keys("5", "4")
	w.dump("vault-doctor", "Vault · doctor (healthy)")
	sops := filepath.Join(w.bin, "sops")
	must(w.t, os.Remove(sops))
	w.reset()
	w.keys("5", "4")
	w.dump("vault-doctor-unhealthy", "Vault · doctor (sops missing)", "key", "edge")
	must(w.t, os.WriteFile(sops, nil, 0o755))
}

// ── more: settings · update · logout · uninstall ──
func walkMore(w *walker) {
	w.flow = "more"
	w.reset()
	w.keys("M")
	w.dump("menu-more", "Menu · More group")
	w.keys("1")
	w.dump("settings", "Settings · cursor on key backend", "key")
	for _, r := range []string{"popup-timeout", "idle-timeout", "harness"} {
		w.keys("down")
		w.dump("settings-"+r, "Settings · cursor on "+r)
	}
	set := func(k int) {
		w.reset()
		w.keys("M", "1")
		for i := 0; i < k; i++ {
			w.keys("down")
		}
		w.keys("enter")
	}
	set(0)
	w.dump("settings-backend-picker", "Settings · key backend picker")
	w.keys("down", "enter")
	w.dump("settings-backend-flash", "Settings · key backend changed (flash)")
	set(1)
	w.dump("settings-popup-picker", "Settings · popup timeout picker")
	w.esc()
	set(2)
	w.dump("settings-idle-picker", "Settings · idle timeout presets")
	w.keys("down", "down", "down", "down", "down", "down", "enter")
	w.dump("settings-idle-custom", "Settings · custom idle timeout input")
	w.esc()
	w.keys("enter", "30s", "enter")
	w.dump("settings-idle-custom-error", "Settings · custom idle timeout too short", "edge")
	w.keys("backspace", "backspace", "backspace", "90m", "enter")
	w.dump("settings-idle-flash", "Settings · idle timeout changed (flash)")
	set(2)
	w.keys("down", "down", "down", "down", "down", "enter")
	w.dump("settings-idle-never-applied", "Settings · idle never applied to the live session")
	walkTTL.Store(0) // back to the default fake TTLs for later screens
	set(3)
	w.dump("settings-harness-picker", "Settings · harness picker")
	w.keys("down", "enter")
	w.dump("settings-harness-flash", "Settings · harness changed (flash)")

	w.reset()
	w.keys("M", "2")
	w.dump("update-checking", "Update · checking")
	w.send("updateCheckMsg", updateCheckMsg{installed: "v1.14.1", latest: "v1.15.0"})
	w.dump("update-confirm", "Update · confirm install", "key")
	w.keys("y")
	w.dump("update-installing", "Update · installing")
	w.send("updateLineMsg", updateLineMsg{line: "… running: dop update --channel stable"})
	w.send("updateLineMsg", updateLineMsg{line: "downloading dop_darwin_arm64.tar.gz (8.4 MB)"})
	w.keys("?")
	w.dump("update-installing-output", "Update · installing (live output)")
	w.send("updateInstallDoneMsg", updateInstallDoneMsg{rc: 1, err: "checksum mismatch for dop_darwin_arm64.tar.gz"})
	w.dump("update-failed", "Update · install failed", "edge")
	w.reset()
	w.keys("M", "2")
	w.send("updateCheckMsg", updateCheckMsg{installed: "v1.14.1", latest: "v1.15.0"})
	w.keys("y")
	w.send("updateInstallDoneMsg", updateInstallDoneMsg{rc: 0})
	w.dump("update-installed", "Update · installed (TUI will exit)")
	w.reset()
	w.keys("M", "2")
	w.send("updateCheckMsg", updateCheckMsg{installed: "v1.14.1", latest: "v1.15.0"})
	w.keys("c")
	w.dump("update-checking-dev", "Update · re-check on dev channel")
	w.reset()
	w.keys("M", "2")
	w.send("updateCheckMsg", updateCheckMsg{installed: "v1.14.1", latest: "v1.14.1"})
	w.dump("update-current", "Update · already up to date")
	w.keys("x")
	w.dump("update-current-flash", "Menu · already up to date (flash)")
	w.reset()
	w.keys("M", "2")
	w.send("updateCheckMsg", updateCheckMsg{err: "GET api.github.com/repos/untoldecay/dop/releases: dial tcp: no route to host"})
	w.dump("update-check-failed", "Update · check failed", "edge")

	w.reset()
	w.keys("M", "3")
	w.dump("menu-logout", "Menu · after logout (locked + flash)")
	w.reset()
	w.keys("M", "4")
	w.dump("uninstall-admin", "Uninstall · confirm (admin install)")
	// default picker choices: enter keeps the current value
	for k := 0; k < 4; k++ {
		set(k)
		w.line("enter")
	}
	w.reset()
	w.keys("M", "2")
	w.send("updateCheckMsg", updateCheckMsg{installed: "v1.14.1", latest: "v1.15.0"})
	w.line("enter")
}

// ── edge: empty vault, overflowing list ──
func walkEdge(w *walker) {
	w.flow = ""
	w.writeVault(walkVaultEmpty)
	must(w.t, os.Rename(w.inviteFile(), w.inviteFile()+".off"))
	list := func(k, slug, title string, tags ...string) {
		w.reset()
		w.keys("3", k)
		w.load()
		w.dump(slug, title, append(tags, "edge")...)
	}
	list("1", "empty-integrations", "Integrations · empty vault", "key")
	list("2", "empty-grants", "Grants · empty vault")
	list("3", "empty-bearers", "Bearers · empty vault")
	w.keys("tab")
	w.dump("empty-bearers-all", "Bearers · empty vault, Revoked tab", "edge")
	w.keys("x")
	w.dump("empty-bearers-prune", "Bearers · nothing to prune", "edge")
	list("4", "empty-team", "Team · no admins")
	w.keys("tab")
	w.dump("empty-team-pending", "Team · no pending invites", "edge")
	w.reset()
	w.keys("2", "agent", "enter")
	w.dump("empty-issue-grants", "Issue · no grants (free-text fallback)", "edge")
	w.reset()
	w.keys("1", "1")
	w.dump("empty-integration-add", "Add integration · empty vault (only New)", "edge")
	w.reset()
	w.keys("1", "2")
	w.dump("empty-grant-add", "Add grant · no integrations", "edge")
	w.esc()
	for _, r := range []struct{ k, slug, title string }{
		{"1", "empty-revoke", "Revoke bearer · nothing active"},
		{"2", "empty-grant-remove", "Remove grant · nothing to remove"},
		{"3", "empty-integration-remove", "Remove credentials · nothing to remove"},
		{"4", "empty-team-remove", "Remove team member · no admins"},
	} {
		w.reset()
		w.keys("4", r.k)
		w.load()
		w.dump(r.slug, r.title, "edge")
	}

	w.writeVault(walkVaultMany())
	list("3", "overflow-bearers", "Bearers · 16 active (overflows 24 rows)", "key")
	for i := 0; i < 15; i++ {
		w.keys("down")
	}
	w.dump("overflow-bearers-bottom", "Bearers · cursor on last row", "edge")
	w.reset()
	w.keys("4", "1")
	w.load()
	w.dump("overflow-revoke", "Revoke bearer · long pick list", "edge")

	w.writeVault(walkVault)
	must(w.t, os.Rename(w.inviteFile()+".off", w.inviteFile()))
}

// ── pending claim banner (last: it sticks to every later menu) ──
func walkPending(w *walker) {
	w.flow = "pending"
	must(w.t, pendingclaim.Write(w.paths, pendingclaim.Record{
		SAS: "472-913", LookupID: "a1b2c3d4e5f60718293a4b5c", CapabilityID: "c0a1b2c3d4e5f6a7b8c9d0e1",
		Subject: "claude-code-laptop", Pubkey: "04d1e2f3a4b5c6d7e8f9a0b1",
		StartedAt: time.Now(), ExpiresAt: time.Now().Add(pendingclaim.TTL), State: pendingclaim.StatePending,
	}))
	w.reset()
	w.dump("pending-banner", "Menu · pending-claim banner", "key")
	w.keys("a")
	w.dump("pending-list", "Pending claims · list")
	w.keys("enter")
	w.dump("pending-pass-empty", "Pending claims · approval passphrase")
	w.esc()
	w.keys("enter", "approve")
	w.dump("pending-pass", "Pending claims · passphrase typed")
	// approve and reject run in a Cmd (dropped here): inject the result.
	w.keys("enter")
	w.dump("pending-approve-running", "Pending claims · approving")
	w.send("pendingResultMsg", pendingResultMsg{})
	w.dump("pending-approve-done", "Pending claims · approved")
	w.reset()
	w.keys("a", "r")
	w.dump("pending-reject-confirm", "Pending claims · reject confirm")
	w.esc()
	w.keys("r", "enter")
	w.dump("pending-reject-running", "Pending claims · rejecting")
	w.send("pendingResultMsg", pendingResultMsg{reject: true, err: "reject: claim already expired"})
	w.dump("pending-reject-error", "Pending claims · reject failed", "edge")
	w.keys("enter")
	w.send("pendingResultMsg", pendingResultMsg{reject: true})
	w.dump("pending-reject-done", "Pending claims · rejected")
}

var walkSpecial = map[string]bool{
	"enter": true, "esc": true, "up": true, "down": true, "left": true,
	"right": true, "tab": true, "shift+tab": true, "backspace": true,
	"ctrl+a": true, "ctrl+u": true,
}

func walkKey(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "ctrl+a":
		return tea.KeyMsg{Type: tea.KeyCtrlA}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	}
	// ponytail: multi-char strings arrive as one paste-like KeyRunes msg;
	// every text field here appends mm.Runes, so that's equivalent to typing.
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// walkLocked makes the fake daemon report a locked session.
var walkLocked atomic.Bool

// walkTTL holds the TTL (seconds, both idle and abs) set via set_ttl; 0 = defaults.
var walkTTL atomic.Int64

// walkDaemon answers the admin socket: status → unlocked session,
// logout → ok, anything else → error (so no decrypt/sign path pretends
// to succeed).
func walkDaemon(t *testing.T, sock string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("fake daemon: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req admin.Request
			resp := admin.Response{Error: "walk: fake daemon"}
			if admin.ReadMessage(c, &req) == nil {
				switch req.Op {
				case admin.OpStatus:
					now := time.Now().Unix()
					idle, abs := int64(1800), int64(8*3600)
					if t := walkTTL.Load(); t > 0 {
						idle, abs = t, t
					}
					data, _ := json.Marshal(admin.StatusResp{
						Unlocked: !walkLocked.Load(), AdminPubkey: walkPubkey,
						AgeRecipient:   "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq",
						IdleTTLSeconds: idle, AbsTTLSeconds: abs,
						StartedAtUnix: now - 600, LastActivityUnix: now,
					})
					resp = admin.Response{OK: true, Data: data}
				case admin.OpLogout:
					resp = admin.Response{OK: true}
				case admin.OpSetTTL:
					var r admin.SetTTLReq
					_ = json.Unmarshal(req.Data, &r)
					walkTTL.Store(r.IdleTTLSeconds) // ponytail: idle stands in for both; walk only sets never
					resp = admin.Response{OK: true}
				}
			}
			_ = admin.WriteMessage(c, resp)
			c.Close()
		}
	}()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var (
	walkEsc    = regexp.MustCompile(`\x1b\[([0-9;]*)m`)
	walkTokRe  = regexp.MustCompile(`(?:^|[^A-Za-z_])token`)
	walkDurRe  = regexp.MustCompile(`\d+m\d+s|\d+[mh]0s\b`)
	walkReset  = regexp.MustCompile(`Reset`)
	walkFooter = regexp.MustCompile(`^\s*(enter|esc|tab|\?|any|space)\b`)
)

// checkScreen asserts contract 24 on one 80x24 dump (mirrors the old
// checkw5.py rules, allowances included).
func checkScreen(t *testing.T, name, text string) {
	t.Helper()
	fail := func(rule string) { t.Errorf("%s: %s", name, rule) }
	lines := strings.Split(text, "\n")
	if len(lines) != 24 {
		fail(fmt.Sprintf("rows=%d", len(lines)))
	}
	bold := 0
	for i, l := range lines {
		plain := walkEsc.ReplaceAllString(l, "")
		if w := ansi.StringWidth(plain); w > 80 {
			fail(fmt.Sprintf("row%d width=%d", i+1, w))
		}
		for _, m := range walkEsc.FindAllStringSubmatch(l, -1) {
			switch strings.Split(m[1], ";")[0] {
			case "3":
				if !strings.HasPrefix(plain, "› ") {
					fail(fmt.Sprintf("italic outside input row%d", i+1))
				}
			case "1":
				bold++
			}
		}
	}
	if bold != 1 {
		fail(fmt.Sprintf("bold=%d", bold))
	}
	plain := walkEsc.ReplaceAllString(text, "")
	for _, g := range "➤⚠✗🔒👤─←→" {
		if strings.ContainsRune(plain, g) {
			fail("glyph " + string(g))
		}
	}
	if walkTokRe.MatchString(plain) {
		fail("lowercase token")
	}
	for rule, bad := range map[string]bool{
		"(s)": strings.Contains(plain, "(s)"), "Reset": walkReset.MatchString(plain),
		"go duration": walkDurRe.MatchString(plain), "backtick": strings.Contains(plain, "`"),
	} {
		if bad {
			fail(rule)
		}
	}
	ft := ""
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			ft = l
		}
	}
	ft = walkEsc.ReplaceAllString(ft, "")
	if strings.Contains(ft, " · ") && walkFooter.MatchString(ft) && len(strings.Split(ft, " · ")) > 5 {
		fail("footer>5")
	}
}
