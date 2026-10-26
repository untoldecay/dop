package approvalcard

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Every surface renders the same fields: effect first, then the rows.
func TestCardRowsAndLines(t *testing.T) {
	c := Card{Kind: KindClaim, Subject: "buzz-reader", Who: "agent key p256 ab12…", Where: "srv1", Code: "AB-CD-EF",
		Touches: "notion.read", Expires: time.Now().Add(5 * time.Minute)}
	rows := c.Rows()
	want := []string{"from", "touches", "code", "answer within"}
	if len(rows) != len(want) {
		t.Fatalf("rows %v", rows)
	}
	for i, r := range rows {
		if r[0] != want[i] {
			t.Fatalf("row %d = %q, want %q", i, r[0], want[i])
		}
	}
	if rows[0][1] != "agent key p256 ab12… on srv1" || rows[2][1] != "AB-CD-EF" {
		t.Fatalf("rows %v", rows)
	}
	if !strings.HasPrefix(c.Body(), "buzz-reader binds to this machine as an agent.\nfrom: ") {
		t.Fatalf("body %q", c.Body())
	}
	if (Card{Kind: KindLease, Where: "srv1"}).Rows()[0][1] != "srv1" {
		t.Fatal("where alone must still fill the from row")
	}
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{45 * time.Second: "45s", 5 * time.Minute: "5m", 10 * time.Minute: "10m", 90 * time.Minute: "1h30m", 20 * time.Hour: "20h", 3 * 24 * time.Hour: "3d"} {
		if got := Human(d); got != want {
			t.Fatalf("Human(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestPrintKindAndLeaseOptions(t *testing.T) {
	if PrintKind("print_env") != KindPrintKeys || PrintKind("print_use") != KindPrintBearer || PrintKind("print_issue") != KindPrintBearer {
		t.Fatal("print kinds")
	}
	o := LeaseOptions()
	if len(o) != len(LeaseDurations) || o[0].Label != "10 min" || o[0].Value != "10m" || o[2].Label != "1 hour" {
		t.Fatalf("lease options %v", o)
	}
}

// The web page carries the card and nothing the agent wrote raw; red
// kinds mark the card so the primary button flips.
func TestPageRendersCard(t *testing.T) {
	var b bytes.Buffer
	c := Card{Kind: KindPrintKeys, Subject: "cam-shell", Who: "dop env"}
	if err := Page(&b, Form{Card: c, Action: "/c/t/approve", RejectAction: "/c/t/reject", Error: "wrong passphrase"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<title>" + c.Title() + "</title>", c.Effect(), c.Footer(), `class="card red"`, Passphrase,
		`action="/c/t/approve"`, `formaction="/c/t/reject"`, "wrong passphrase", "<dt>from</dt><dd>dop env</dd>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("page lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<select") {
		t.Fatal("no options → no select")
	}
	b.Reset()
	_ = Page(&b, Form{Card: Card{Kind: KindLease, Subject: "cam-shell", Who: "buzz", Options: LeaseOptions()}})
	if !strings.Contains(b.String(), `<option value="10m" selected>10 min</option>`) {
		t.Fatalf("lease page lacks the preselected option:\n%s", b.String())
	}
}
