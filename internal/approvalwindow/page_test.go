package approvalwindow

import (
	"strings"
	"testing"

	"github.com/fray/dop/internal/approvalcard"
)

func TestPageCarriesTheCardAndNoRawScriptBreak(t *testing.T) {
	req := Request{Card: approvalcard.Card{Kind: approvalcard.KindLease, Subject: "cam-shell", Who: "buzz </script> x", Where: "srv1",
		Options: approvalcard.LeaseOptions()}, Lease: true, TimeoutMs: 60000}
	html := Page(req)
	for _, want := range []string{"DOP — lease request", "buzz", "10 min", `"lease":true`, "const D = {"} {
		if !strings.Contains(html, want) {
			t.Fatalf("page lacks %q", want)
		}
	}
	if strings.Contains(html, "</script> x") {
		t.Fatal("a </script> inside the data must be escaped")
	}
	if strings.Contains(html, "/*DOP_DATA*/null") {
		t.Fatal("placeholder not replaced")
	}
}
