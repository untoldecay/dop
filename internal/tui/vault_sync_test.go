// Screen-entry vault sync: due only for a git vault with a stale
// last-pull.ts; a due sync holds the screen until vaultSyncedMsg.

package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

func syncPaths(t *testing.T, withGit bool) *config.Paths {
	t.Helper()
	root := t.TempDir()
	p := &config.Paths{Root: root, Vault: filepath.Join(root, "vault")}
	if withGit {
		if err := os.MkdirAll(filepath.Join(p.Vault, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func stampPull(t *testing.T, p *config.Paths, age time.Duration) {
	t.Helper()
	m := filepath.Join(p.Root, "last-pull.ts")
	if err := os.WriteFile(m, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Add(-age)
	_ = os.Chtimes(m, ts, ts)
}

func TestVaultSyncDue(t *testing.T) {
	if vaultSyncDue(syncPaths(t, false)) {
		t.Error("no .git → never due")
	}
	p := syncPaths(t, true)
	if !vaultSyncDue(p) {
		t.Error("never pulled → due")
	}
	stampPull(t, p, 2*time.Second)
	if vaultSyncDue(p) {
		t.Error("pulled 2s ago → not due")
	}
	stampPull(t, p, time.Minute)
	if !vaultSyncDue(p) {
		t.Error("pulled 1m ago → due")
	}
	t.Setenv("DOP_NO_AUTO_PULL", "1")
	if vaultSyncDue(p) {
		t.Error("DOP_NO_AUTO_PULL=1 → never due")
	}
}

func TestSyncThenOpensNowWhenFresh(t *testing.T) {
	p := syncPaths(t, true)
	stampPull(t, p, 0)
	m := &rootModel{paths: p}
	opened := false
	m.syncThen(func(*rootModel) (tea.Model, tea.Cmd) { opened = true; return m, nil })
	if !opened || m.pendingSyncFn != nil {
		t.Fatal("fresh vault should open the screen immediately")
	}
}

func TestSyncThenWaitsForPull(t *testing.T) {
	m := &rootModel{paths: syncPaths(t, true)}
	opened := false
	_, cmd := m.syncThen(func(*rootModel) (tea.Model, tea.Cmd) { opened = true; return m, nil })
	if opened || cmd == nil || m.pendingSyncFn == nil {
		t.Fatal("stale vault should pull first")
	}
	m.Update(press("enter"))
	if opened {
		t.Fatal("keys must not open anything while the pull runs")
	}
	m.Update(vaultSyncedMsg{note: "team vault changed: 1 conflict(s)"})
	if !opened || m.pendingSyncFn != nil {
		t.Fatal("vaultSyncedMsg should open the pending screen")
	}
	if m.st.flash != "team vault changed: 1 conflict(s)" {
		t.Fatalf("conflict note should reach the status line, got %q", m.st.flash)
	}
}
