// Settings view — rc7l rewrite.
//
// Pre-rc7l, each setting had a keyboard key (f / t / h) that cycled or
// toggled the value. That's compact but breaks the DOP TUI's otherwise-
// consistent cursor-based select pattern (grants, integration kind,
// protection, scope presets, etc. all use the vertical-list → ↑↓ →
// enter idiom). Operators had to learn a different control for each
// setting.
//
// This rewrite is two-state:
//
//   listMode (default)
//     ↑↓ moves the cursor between settings. Each row shows the
//     current value in brackets. Enter opens the picker for the row
//     under the cursor.
//
//   pickerMode
//     ↑↓ moves between choices for the current setting. Enter commits
//     and returns to list. Esc returns without saving.
//     Special case: picking "custom…" on AdminIdleTTL opens a text
//     input (customMode) accepting durations like "2h" / "90m" / "never".
//
// Four settings:
//   - Allow extractable file-backed P-256 agent keys  (bool)
//   - Approval popup timeout  (15 / 30 / 60 s)
//   - Admin session idle timeout  (preset + custom + never)
//   - Harness  (claude-code / codex / opencode / manual / any / none)

package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

type settingsMode int

const (
	settingsModeList   settingsMode = 0
	settingsModePicker settingsMode = 1
	settingsModeCustom settingsMode = 2 // text input for custom AdminIdleTTL
)

// Row indices. Order defines on-screen order.
const (
	settingRowFileKeys = iota
	settingRowApprovalTimeout
	settingRowAdminIdleTTL
	settingRowHarness
	settingRowCount
)

type settingsView struct {
	wiz   // size, for the custom duration step
	paths *config.Paths
	prefs Prefs
	mode  settingsMode

	// list-mode state
	rowCursor int

	// picker-mode state
	pickerRow    int // which setting the picker is open for
	pickerCursor int // index within that setting's choices

	// custom-input state (for AdminIdleTTL custom...)
	customBuf textinput.Model
	customErr string

	done  bool
	flash string
	err   string
}

func newSettingsView(p *config.Paths) *settingsView {
	v := &settingsView{paths: p, prefs: LoadPrefs(p), customBuf: newFormInput(false)}
	v.customBuf.Placeholder = "90m"
	return v
}

func (v *settingsView) Init() tea.Cmd { return nil }
func (v *settingsView) Done() bool    { return v.done }
func (v *settingsView) Flash() string { return v.flash }

func (v *settingsView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.mode == settingsModeCustom); ok {
		return v, cmd
	}
	mm, ok := msg.(tea.KeyMsg)
	if !ok {
		return v, nil
	}
	if k := mm.String(); k != "esc" && k != "q" {
		v.flash, v.err = "", ""
	}
	// Universal escapes.
	switch mm.String() {
	case "ctrl+c":
		v.done = true
		return v, nil
	}
	switch v.mode {
	case settingsModeCustom:
		return v.updateCustom(mm)
	case settingsModePicker:
		return v.updatePicker(mm)
	default:
		return v.updateList(mm)
	}
}

func (v *settingsView) updateList(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc", "q":
		v.done = true
		return v, nil
	case "up", "k":
		if v.rowCursor > 0 {
			v.rowCursor--
		}
	case "down", "j":
		if v.rowCursor < settingRowCount-1 {
			v.rowCursor++
		}
	case "enter":
		v.openPicker(v.rowCursor)
	}
	return v, nil
}

func (v *settingsView) updatePicker(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	choices := v.choicesFor(v.pickerRow)
	switch mm.String() {
	case "esc":
		v.mode = settingsModeList
		return v, nil
	case "up", "k":
		if v.pickerCursor > 0 {
			v.pickerCursor--
		}
	case "down", "j":
		if v.pickerCursor < len(choices)-1 {
			v.pickerCursor++
		}
	case "enter":
		pick := choices[v.pickerCursor]
		if pick.isCustom {
			v.mode = settingsModeCustom
			v.customBuf.Reset()
			v.customErr = ""
			return v, nil
		}
		v.applyPick(v.pickerRow, pick)
		v.mode = settingsModeList
	}
	return v, nil
}

func (v *settingsView) updateCustom(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	if mm.String() != "enter" {
		v.customErr = ""
	}
	switch mm.String() {
	case "esc":
		// Back to picker list (not all the way to settings list — if the
		// operator opened the picker on purpose, they likely still want
		// to pick something).
		v.mode = settingsModePicker
		v.customErr = ""
		return v, nil
	case "enter":
		secs, err := userprefs.ParseAdminIdleTTL(v.customBuf.Value())
		if err != nil {
			v.customErr = err.Error()
			return v, nil
		}
		v.prefs.AdminIdleTTLSeconds = secs
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.customErr = "save: " + err.Error()
			return v, nil
		}
		v.flash = "Admin idle timeout set to " + shortDur(userprefs.AdminIdleTTLLabel(secs))
		v.mode = settingsModeList
		return v, nil
	default:
		edit(&v.customBuf, mm)
	}
	return v, nil
}

// openPicker transitions to picker mode for the given row AND sets the
// cursor to the choice that matches the current pref value (so enter
// without moving commits a no-op, not a surprise change).
func (v *settingsView) openPicker(row int) {
	v.pickerRow = row
	v.pickerCursor = v.currentChoiceIndex(row)
	v.mode = settingsModePicker
}

type settingChoice struct {
	label    string
	desc     string // muted, same row in the picker
	value    string // internal canonical value (for logging / lookup)
	isCustom bool   // true → enter opens text input instead of committing
}

func (v *settingsView) choicesFor(row int) []settingChoice {
	switch row {
	case settingRowFileKeys:
		return []settingChoice{
			{label: "Default", desc: "Secure Enclave or ed25519", value: "no"},
			{label: "File-backed P-256", desc: "extractable key, allowed on this machine", value: "yes"},
		}
	case settingRowApprovalTimeout:
		out := []settingChoice{}
		for _, s := range userprefs.ApprovalTimeoutChoices {
			out = append(out, settingChoice{
				label: approvalTimeoutLabel(s),
				value: approvalTimeoutLabel(s),
			})
		}
		return out
	case settingRowAdminIdleTTL:
		out := []settingChoice{}
		for _, s := range userprefs.AdminIdleTTLChoices {
			out = append(out, settingChoice{
				label: shortDur(userprefs.AdminIdleTTLLabel(s)),
				value: userprefs.AdminIdleTTLLabel(s),
			})
		}
		out = append(out, settingChoice{label: "Custom…", desc: "type a duration such as 2h", value: "custom", isCustom: true})
		return out
	case settingRowHarness:
		out := []settingChoice{}
		for _, h := range userprefs.HarnessChoices {
			out = append(out, settingChoice{
				label: harnessShort(h),
				desc:  harnessDesc(h),
				value: h,
			})
		}
		return out
	}
	return nil
}

// currentChoiceIndex returns the index of the choice in choicesFor(row)
// that matches the current pref value. Returns 0 when nothing matches.
func (v *settingsView) currentChoiceIndex(row int) int {
	switch row {
	case settingRowFileKeys:
		if v.prefs.AllowFileKeys {
			return 1
		}
		return 0
	case settingRowApprovalTimeout:
		cur := v.prefs.ApprovalPopupTimeoutSeconds
		if cur == 0 {
			cur = userprefs.ApprovalTimeoutDefaultSeconds
		}
		for i, s := range userprefs.ApprovalTimeoutChoices {
			if s == cur {
				return i
			}
		}
	case settingRowAdminIdleTTL:
		cur := v.prefs.AdminIdleTTLSeconds
		for i, s := range userprefs.AdminIdleTTLChoices {
			if s == cur {
				return i
			}
		}
		if cur == 0 {
			return 0 // default row
		}
	case settingRowHarness:
		for i, h := range userprefs.HarnessChoices {
			if h == v.prefs.Harness {
				return i
			}
		}
	}
	return 0
}

func (v *settingsView) applyPick(row int, pick settingChoice) {
	switch row {
	case settingRowFileKeys:
		v.prefs.AllowFileKeys = pick.value == "yes"
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.err = err.Error()
			return
		}
		if v.prefs.AllowFileKeys {
			v.flash = "Agent key backend set to file-backed P-256"
		} else {
			v.flash = "Agent key backend set to default"
		}
	case settingRowApprovalTimeout:
		for _, s := range userprefs.ApprovalTimeoutChoices {
			if approvalTimeoutLabel(s) == pick.value {
				v.prefs.ApprovalPopupTimeoutSeconds = s
				if err := SavePrefs(v.paths, v.prefs); err != nil {
					v.err = err.Error()
					return
				}
				v.flash = "Approval popup timeout set to " + shortDur(pick.value)
				return
			}
		}
	case settingRowAdminIdleTTL:
		for _, s := range userprefs.AdminIdleTTLChoices {
			if userprefs.AdminIdleTTLLabel(s) == pick.value {
				v.prefs.AdminIdleTTLSeconds = s
				if err := SavePrefs(v.paths, v.prefs); err != nil {
					v.err = err.Error()
					return
				}
				v.flash = "Admin idle timeout set to " + shortDur(pick.value) + ", effective at the next login"
				return
			}
		}
	case settingRowHarness:
		v.prefs.Harness = pick.value
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.err = err.Error()
			return
		}
		v.flash = "Harness set to " + harnessShort(pick.value)
	}
}

func approvalTimeoutLabel(s int) string {
	return humanDur(s)
}

func humanDur(secs int) string {
	switch {
	case secs < 60:
		return intToStr(secs) + "s"
	case secs%60 == 0:
		return intToStr(secs/60) + "m"
	default:
		return intToStr(secs) + "s"
	}
}

func intToStr(n int) string {
	// Avoid pulling fmt for one int.
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// --- View ---

var settingsKeys = keyMap{
	short: []key.Binding{hint("enter", "change"), keyBack},
	full:  [][]key.Binding{{hint("enter", "change"), keyBack}, {keyMove}},
}

// shortDur turns the preference labels into 15m / 4h.
func shortDur(s string) string {
	s = strings.NewReplacer(" min", "m", " h", "h").Replace(s)
	if d, err := time.ParseDuration(s); err == nil {
		return shortDuration(d)
	}
	return s
}

func harnessShort(h string) string {
	if n, ok := map[string]string{userprefs.HarnessManual: "Manual", userprefs.HarnessAny: "Any", userprefs.HarnessNone: "None"}[h]; ok {
		return n
	}
	return userprefs.HarnessLabel(h)
}

func harnessDesc(h string) string {
	return map[string]string{userprefs.HarnessManual: "set DOP_SESSION_ID yourself", userprefs.HarnessAny: "try all recognized adapters", userprefs.HarnessNone: "skip the session check"}[h]
}

func (v *settingsView) View() string {
	if v.mode == settingsModeCustom {
		return v.viewCustom()
	}
	rows := []struct{ label, value, hint string }{
		{"Agent key backend", v.rowValueFileKeys(), "default: Secure Enclave or ed25519 · alternative: file-backed P-256"},
		{"Approval popup timeout", v.rowValueApprovalTimeout(), "how long the approval dialog waits before moving to the phone"},
		{"Admin idle timeout", v.rowValueAdminIdleTTL(), v.idleHint()},
		{"Harness", v.rowValueHarness(), "which session variable dop reads for the trust cache"},
	}
	st := status{err: v.err, flash: v.flash}
	var body []string
	ctx := ""
	if v.mode == settingsModePicker {
		ctx = rows[v.pickerRow].label
		var opts [][2]string
		for _, c := range v.choicesFor(v.pickerRow) {
			opts = append(opts, [2]string{c.label, c.desc})
		}
		body = optRows(opts, v.pickerCursor)
	} else {
		st.setHint(rows[v.rowCursor].hint)
		for i, r := range rows {
			if i == v.rowCursor {
				body = append(body, focusSt.Render("› "+padTrunc(r.label, 26))+"  "+bodySt.Render(r.value))
			} else {
				body = append(body, "  "+bodySt.Render(padTrunc(r.label, 26))+"  "+mutedSt.Render(r.value))
			}
		}
	}
	km := settingsKeys
	if v.mode == settingsModePicker {
		km = keyMap{short: []key.Binding{hint("enter", "pick"), keyBack}, full: [][]key.Binding{{hint("enter", "pick"), keyBack}, {keyMove}}}
	}
	body = km.overlay(body, v.width, frameRows(v.height), v.help)
	return frame(v.width, v.height, "Settings", nil, ctx, body, st.String(), km.footerLine(v.width, v.help))
}

func (v *settingsView) viewCustom() string {
	return v.screen("Idle timeout", "", "Admin session idle timeout", []string{inputRow(&v.customBuf)},
		"A duration such as 15m, 2h or 24h, at least 1m; never for manual logout only.",
		strings.ReplaceAll(v.customErr, "`", ""), "", wizKeys("save"))
}

func (v *settingsView) rowValueFileKeys() string {
	if v.prefs.AllowFileKeys {
		return "file-backed P-256"
	}
	return "default"
}
func (v *settingsView) rowValueApprovalTimeout() string {
	s := v.prefs.ApprovalPopupTimeoutSeconds
	if s == 0 {
		s = userprefs.ApprovalTimeoutDefaultSeconds
	}
	return humanDur(s)
}
func (v *settingsView) rowValueAdminIdleTTL() string {
	return shortDur(userprefs.AdminIdleTTLLabel(v.prefs.AdminIdleTTLSeconds))
}

// idleHint says what the idle pick means, the absolute cap included.
func (v *settingsView) idleHint() string {
	if v.prefs.AdminIdleTTLSeconds == userprefs.AdminIdleTTLNever {
		return "manual logout only; the session also never expires on its own"
	}
	return fmt.Sprintf("unlocked until idle this long; sessions also end %dm after login", int(admin.DefaultAbsTTL.Minutes()))
}

func (v *settingsView) rowValueHarness() string {
	if v.prefs.Harness == "" {
		return "unset"
	}
	return userprefs.HarnessLabel(v.prefs.Harness)
}
