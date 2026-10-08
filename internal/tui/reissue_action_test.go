// One "Re-issue" entry on the bearer detail: unclaimed → new PIN;
// claimed → keep the agent's key (P-256 only) or start a new claim.

package tui

import (
	"reflect"
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

func optionKeys(b *vault.Binding) []string {
	var ks []string
	for _, o := range reissueOptions(vault.Capability{Binding: b}) {
		ks = append(ks, o.key)
	}
	return ks
}

func TestReissueEntry(t *testing.T) {
	cases := []struct {
		name    string
		binding *vault.Binding
		entry   bool
		options []string
	}{
		{"claimed p256", &vault.Binding{Kind: "pin", Pubkey: "04ab", KeyType: vault.KeyTypeP256}, true, []string{"rotate", "reclaim"}},
		{"claimed ed25519", &vault.Binding{Kind: "pin", Pubkey: "ab", KeyType: vault.KeyTypeEd25519}, true, []string{"reclaim"}},
		{"rotated p256 (pubkey-bound)", &vault.Binding{Kind: "pubkey", Pubkey: "04ab", KeyType: vault.KeyTypeP256}, true, []string{"rotate", "reclaim"}},
		{"unclaimed pin", &vault.Binding{Kind: "pin"}, true, nil},
		{"unbound", nil, false, nil},
	}
	for _, c := range cases {
		if got := actionKeys(c.binding)["p"]; got != c.entry {
			t.Errorf("%s: Re-issue entry = %v, want %v", c.name, got, c.entry)
		}
		if got := optionKeys(c.binding); !reflect.DeepEqual(got, c.options) {
			t.Errorf("%s: options = %v, want %v", c.name, got, c.options)
		}
	}
}
