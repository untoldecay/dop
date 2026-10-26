// Package approvalcard is the one description of "a question for the
// operator" that every approval surface renders — native dialog, CLI,
// TUI, web page, later the phone (contract 27). Surfaces differ in
// layout; the fields, the per-kind wording and the mood are decided
// here, once.
package approvalcard

import (
	"fmt"
	"strings"
	"time"
)

// Kind is the closed set of things an operator can be asked to approve.
type Kind string

const (
	KindClaim          Kind = "claim"           // an agent binds a PIN bearer on this machine
	KindRemoteClaim    Kind = "remote-claim"    // an agent binds a PIN bearer on a server
	KindLease          Kind = "lease"           // a server asks to use a portable bearer for a while
	KindProtectedGrant Kind = "protected-grant" // a bearer is issued with a protected grant
	KindPrintBearer    Kind = "print-bearer"    // a bearer value is about to be printed
	KindPrintKeys      Kind = "print-keys"      // upstream keys are about to be printed into a transcript
)

// Mood tells a surface how loud to be. Green is routine, amber asks
// for a second look, red changes the primary action to refuse.
type Mood string

const (
	MoodRoutine Mood = "routine"
	MoodAmber   Mood = "amber"
	MoodRed     Mood = "red"
)

// Option is one answer the operator may pick besides approve / deny
// (the lease durations). The agent never fills these.
type Option struct {
	Label, Value string
}

// Card is the question. Every field is operator-facing text, already
// resolved: no ids to look up, no secrets.
type Card struct {
	Kind    Kind
	Subject string    // the bearer / agent name
	Who     string    // who asks: agent name, "signed by its agent key" / "unsigned"
	Where   string    // host · harness
	Touches string    // services / grants concerned
	Code    string    // a code the operator compares with the agent's screen (the claim SAS)
	Expires time.Time // when the question stops being valid (zero = none)
	Options []Option  // e.g. lease durations; empty = plain approve / deny
	Default int       // index into Options the surface preselects
}

// Mood of the kind. Printing keys is the one red action dop has.
func (c Card) Mood() Mood {
	switch c.Kind {
	case KindPrintKeys, KindPrintBearer:
		return MoodRed
	case KindProtectedGrant:
		return MoodAmber
	}
	return MoodRoutine
}

// Title is the window / screen title. Always names dop, never imitates
// a system prompt.
func (c Card) Title() string {
	switch c.Kind {
	case KindClaim:
		return "DOP — agent claim"
	case KindRemoteClaim:
		return "DOP — remote agent claim"
	case KindLease:
		return "DOP — lease request"
	case KindProtectedGrant:
		return "DOP — protected grant"
	case KindPrintBearer:
		return "DOP — print a bearer"
	case KindPrintKeys:
		return "DOP — print keys into a transcript"
	}
	return "DOP — approval"
}

// Effect is the first line: what happens if the operator says yes, as a
// verb, with the subject.
func (c Card) Effect() string {
	switch c.Kind {
	case KindClaim:
		return fmt.Sprintf("%s binds to this machine as an agent.", c.Subject)
	case KindRemoteClaim:
		return fmt.Sprintf("%s binds to %s as an agent.", c.Subject, firstWord(c.Where))
	case KindLease:
		return fmt.Sprintf("%s gets a short-lived bearer with the grants of %s.", firstWord(c.Who), c.Subject)
	case KindProtectedGrant:
		return fmt.Sprintf("A bearer for %s is issued with a protected grant.", c.Subject)
	case KindPrintBearer:
		return fmt.Sprintf("The bearer of %s is printed where this shell's output goes.", c.Subject)
	case KindPrintKeys:
		return fmt.Sprintf("The keys behind %s are printed into an AI transcript.", c.Subject)
	}
	return c.Subject
}

// Rows is the body every surface shows under the effect, as label /
// value pairs: who and where, what it touches, the code to compare,
// until when. Empty fields are skipped.
func (c Card) Rows() [][2]string {
	var out [][2]string
	add := func(k, v string) {
		if v != "" {
			out = append(out, [2]string{k, v})
		}
	}
	from := c.Who
	switch {
	case c.Who != "" && c.Where != "":
		from = c.Who + " on " + c.Where
	case c.Where != "":
		from = c.Where
	}
	add("from", from)
	add("touches", c.Touches)
	add("code", c.Code)
	if !c.Expires.IsZero() {
		if left := time.Until(c.Expires); left > 0 {
			add("answer within", Human(left))
		}
	}
	return out
}

// Lines is Rows as "label: value" text, for dialogs and CLI prompts.
func (c Card) Lines() []string {
	var out []string
	for _, r := range c.Rows() {
		out = append(out, r[0]+": "+r[1])
	}
	return out
}

// Passphrase is the one label every surface puts on the field.
const Passphrase = "Approval passphrase"

// LeaseDurations are the leases the operator can grant, shortest first;
// the CLI clamps to the bearer's cap. The agent never picks.
var LeaseDurations = []string{"10m", "30m", "1h"}

// LeaseOptions is LeaseDurations as options, labelled for a human.
func LeaseOptions() []Option {
	labels := map[string]string{"10m": "10 min", "30m": "30 min", "1h": "1 hour"}
	out := make([]Option, 0, len(LeaseDurations))
	for _, d := range LeaseDurations {
		l := labels[d]
		if l == "" {
			l = d
		}
		out = append(out, Option{Label: l, Value: d})
	}
	return out
}

// PrintKind maps a print guard surface ("print_use", "print_issue",
// "print_claim", "print_env") to the card kind: printing scoped env is
// the keys themselves, everything else prints a bearer.
func PrintKind(surface string) Kind {
	if surface == "print_env" {
		return KindPrintKeys
	}
	return KindPrintBearer
}

// Body is Effect + Lines as one block, for dialogs and CLI prompts.
func (c Card) Body() string {
	return strings.Join(append([]string{c.Effect()}, c.Lines()...), "\n")
}

// Footer is the one line that says what approving means for the
// secret, so the operator reads it before the passphrase field.
func (c Card) Footer() string {
	switch c.Kind {
	case KindLease:
		return "The bearer dies when the lease ends; the agent asks again."
	case KindPrintKeys:
		return "Prefer dop exec: the agent can use the keys without seeing them."
	}
	return ""
}

// Human is the duration as people read it: "45s", "5m", "1h30m", "20h",
// "3d" — never Go's "5m0s" (TUI contract 24).
func Human(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := strings.TrimSuffix(d.String(), "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " ·"); i > 0 {
		return s[:i]
	}
	return s
}
