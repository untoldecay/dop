// Rotate bearer shows only where `dop token rotate` works: claimed
// P-256 bearers. Unclaimed ones re-issue through Repin.

package tui

import (
	"testing"

	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/vault"
)

func actionKeys(b *vault.Binding) map[string]bool {
	v := &listView{capabilities: []vault.Capability{{Status: capability.RecordStatusActive, Binding: b}}}
	keys := map[string]bool{}
	for _, a := range v.currentActions() {
		keys[a.key] = true
	}
	return keys
}

func TestRotateActionOnlyForClaimedP256(t *testing.T) {
	cases := []struct {
		name    string
		binding *vault.Binding
		rotate  bool
		repin   bool
	}{
		{"claimed p256", &vault.Binding{Kind: "pin", Pubkey: "04ab", KeyType: vault.KeyTypeP256}, true, false},
		{"claimed ed25519", &vault.Binding{Kind: "pin", Pubkey: "ab", KeyType: vault.KeyTypeEd25519}, false, false},
		{"unclaimed pin", &vault.Binding{Kind: "pin"}, false, true},
		{"unbound", nil, false, false},
	}
	for _, c := range cases {
		k := actionKeys(c.binding)
		if k["t"] != c.rotate || k["p"] != c.repin {
			t.Errorf("%s: rotate=%v repin=%v, want rotate=%v repin=%v", c.name, k["t"], k["p"], c.rotate, c.repin)
		}
	}
}
