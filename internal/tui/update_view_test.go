// Channel flip must be reachable when the check lands straight on the
// done screen (already on latest stable) — otherwise dev is unreachable.

package tui

import (
	"strings"
	"testing"
)

func TestUpdateFlipFromAlreadyLatest(t *testing.T) {
	v := newUpdateView(nil)
	v.Update(updateCheckMsg{installed: "v1.14.1", latest: "v1.14.1"})
	if v.step != updateStepDone {
		t.Fatalf("want done step, got %v", v.step)
	}
	if !strings.Contains(v.View(), "c channel") {
		t.Fatal("done screen should advertise c")
	}
	_, cmd := v.Update(press("c"))
	if v.Done() || v.channel != "dev" || v.step != updateStepChecking || cmd == nil {
		t.Fatalf("c should flip to dev and re-check: done=%v channel=%s step=%v", v.Done(), v.channel, v.step)
	}
	if v.flash != "" || v.installed != "" {
		t.Fatal("stale check result should be cleared")
	}
}

func TestUpdateFlipFromCheckError(t *testing.T) {
	v := newUpdateView(nil)
	v.Update(updateCheckMsg{err: "boom"})
	v.Update(press("c"))
	if v.Done() || v.channel != "dev" {
		t.Fatal("c should flip after a failed check")
	}
}

func TestUpdateDoneOtherKeyLeaves(t *testing.T) {
	v := newUpdateView(nil)
	v.Update(updateCheckMsg{installed: "v1.14.1", latest: "v1.14.1"})
	v.Update(press("x"))
	if !v.Done() {
		t.Fatal("non-c key should leave the done screen")
	}
}

func TestUpdateNoFlipAfterFailedInstall(t *testing.T) {
	v := newUpdateView(nil)
	v.Update(updateCheckMsg{installed: "v1.14.1", latest: "v1.14.2"})
	v.Update(updateInstallDoneMsg{rc: 1, err: "checksum"})
	if v.canFlipFromDone() {
		t.Fatal("failed install is not a flip-able state")
	}
}
