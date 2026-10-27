package tui

import (
	"testing"

	"github.com/fray/dop/internal/config"
)

// A screen reloads only while idle: a form or an action in progress is
// never torn down by the freshness tick.
func TestReloadOnlyWhenIdle(t *testing.T) {
	paths := &config.Paths{Root: t.TempDir(), Vault: t.TempDir()}
	l := newListView(nil, paths)
	if l.Reload() == nil {
		t.Fatal("bearer list must reload while listing")
	}
	l.mode = listModePendPass
	if l.Reload() != nil {
		t.Fatal("no reload while typing a passphrase")
	}
	p := &pendingView{paths: paths}
	if p.Reload() == nil {
		t.Fatal("pending picker must reload")
	}
	p.step = pendingStepPass
	if p.Reload() != nil {
		t.Fatal("no reload during the passphrase step")
	}
	var _ reloader = &integrationListView{}
	var _ reloader = &grantListView{}
	var _ reloader = &teamListView{}
}
