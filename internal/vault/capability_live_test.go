package vault

import (
	"testing"
	"time"
)

// An expired lease bearer leaves the Active list and ages from its expiry.
func TestCapabilityExpiredLeavesActive(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	c := Capability{Status: "active", ExpiresAt: past}
	if c.Live() || !c.Expired() || !c.TouchedAt().Equal(past) {
		t.Fatalf("expired active: live=%v expired=%v touched=%v", c.Live(), c.Expired(), c.TouchedAt())
	}
	c = Capability{Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if !c.Live() || c.Expired() {
		t.Fatal("future expiry must stay live")
	}
	c = Capability{Status: "revoked", ExpiresAt: past}
	if c.Live() || c.Expired() {
		t.Fatal("a revoked record is neither live nor 'expired'")
	}
}
