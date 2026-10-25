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

// Lines is the body every text surface shows under the effect:
// who, where, what it touches, until when. Empty fields are skipped.
func (c Card) Lines() []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+": "+v)
		}
	}
	add("from", strings.TrimSpace(strings.Join([]string{c.Who, c.Where}, " on ")))
	add("touches", c.Touches)
	if !c.Expires.IsZero() {
		if left := time.Until(c.Expires).Round(time.Minute); left > 0 {
			add("answer within", left.String())
		}
	}
	return out
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

func firstWord(s string) string {
	if i := strings.IndexAny(s, " ·"); i > 0 {
		return s[:i]
	}
	return s
}
