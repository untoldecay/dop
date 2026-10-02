// v1.13.0-rc14 — handoff text builder. Isolated from view.go so a
// unit test can grep-assert the contract shape without constructing
// a full tea.Model. See _rules/_requirements/contracts/13_handoff_text_shape.md.

package tui

// buildHandoffText produces the string pasted into the receiving
// agent's chat. Shape is intentionally minimal — a one-line preface
// + the bearer + the PIN (if present) + exactly one `dop claim`
// command. Nothing imperative after the command, so sandbox prompt-
// injection detectors on the receiving side don't block it.
//
// bearer: the issued bearer (always non-empty on this path).
// pin: short claim PIN; empty when the token was issued --no-bind.
// allowFileKeys: when true, embed DOP_ALLOW_FILE_KEYS=1 + --key-type p256
// in the single command (never on a separate explanatory line).
func buildHandoffText(bearer, pin string, allowFileKeys bool) string {
	claimCmd := "DOP_TOKEN=" + bearer + " dop claim " + pin
	if allowFileKeys {
		claimCmd = "DOP_TOKEN=" + bearer + " DOP_ALLOW_FILE_KEYS=1 dop claim --key-type p256 " + pin
	}
	return "Scoped credential access via DOP — run:\n\n" +
		"  " + claimCmd
}
