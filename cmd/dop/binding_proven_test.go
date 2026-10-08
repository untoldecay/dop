package main

import (
	"testing"

	"github.com/fray/dop/internal/capability"
)

func TestBindingProven(t *testing.T) {
	cases := []struct {
		binding *capability.EnvelopeBinding
		want    bool
	}{
		{nil, false},
		{&capability.EnvelopeBinding{Kind: ""}, false},
		{&capability.EnvelopeBinding{Kind: "none"}, false},
		{&capability.EnvelopeBinding{Kind: "pin", Pubkey: "ab"}, true},
		{&capability.EnvelopeBinding{Kind: "pubkey", Pubkey: "ab"}, true},
	}
	for _, c := range cases {
		if got := bindingProven(resolveResult{binding: c.binding}); got != c.want {
			t.Errorf("bindingProven(%+v) = %v, want %v", c.binding, got, c.want)
		}
	}
}
