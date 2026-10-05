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
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

type settingsMode int

const (
	settingsModeList    settingsMode = 0
	settingsModePicker  settingsMode = 1
	settingsModeCustom  settingsMode = 2 // text input for custom AdminIdleTTL
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
	paths *config.Paths
	prefs Prefs
	mode  settingsMode

	// list-mode state
	rowCursor int

	// picker-mode state
	pickerRow    int // which setting the picker is open for
	pickerCursor int // index within that setting's choices

	// custom-input state (for AdminIdleTTL custom...)
	customBuf strings.Builder
	customErr string

	done  bool
	flash string
	err   string
}

func newSettingsView(p *config.Paths) *settingsView {
	return &settingsView{paths: p, prefs: LoadPrefs(p)}
}

func (v *settingsView) Init() tea.Cmd { return nil }
func (v *settingsView) Done() bool    { return v.done }
func (v *settingsView) Flash() string { return v.flash }

func (v *settingsView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	mm, ok := msg.(tea.KeyMsg)
	if !ok {
		return v, nil
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
	switch mm.String() {
	case "esc":
		// Back to picker list (not all the way to settings list — if the
		// operator opened the picker on purpose, they likely still want
		// to pick something).
		v.mode = settingsModePicker
		v.customErr = ""
		return v, nil
	case "enter":
		secs, err := userprefs.ParseAdminIdleTTL(v.customBuf.String())
		if err != nil {
			v.customErr = err.Error()
			return v, nil
		}
		v.prefs.AdminIdleTTLSeconds = secs
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.customErr = "save: " + err.Error()
			return v, nil
		}
		v.flash = "admin idle timeout → " + userprefs.AdminIdleTTLLabel(secs)
		v.mode = settingsModeList
		return v, nil
	case "backspace":
		s := v.customBuf.String()
		if len(s) > 0 {
			v.customBuf.Reset()
			v.customBuf.WriteString(s[:len(s)-1])
		}
	default:
		if len(mm.Runes) > 0 {
			v.customBuf.WriteString(string(mm.Runes))
		}
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
	value    string // internal canonical value (for logging / lookup)
	isCustom bool   // true → enter opens text input instead of committing
}

func (v *settingsView) choicesFor(row int) []settingChoice {
	switch row {
	case settingRowFileKeys:
		return []settingChoice{
			{label: "no — default (SE on signed macOS, else ed25519)", value: "no"},
			{label: "yes — allow extractable file-backed P-256", value: "yes"},
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
				label: userprefs.AdminIdleTTLLabel(s),
				value: userprefs.AdminIdleTTLLabel(s),
			})
		}
		out = append(out, settingChoice{label: "custom…", value: "custom", isCustom: true})
		return out
	case settingRowHarness:
		out := []settingChoice{}
		for _, h := range userprefs.HarnessChoices {
			out = append(out, settingChoice{
				label: userprefs.HarnessLabel(h),
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
			v.flash = "allow-file-keys ON — new TUI tokens will recommend --key-type p256"
		} else {
			v.flash = "allow-file-keys OFF — default key backend"
		}
	case settingRowApprovalTimeout:
		for _, s := range userprefs.ApprovalTimeoutChoices {
			if approvalTimeoutLabel(s) == pick.value {
				v.prefs.ApprovalPopupTimeoutSeconds = s
				if err := SavePrefs(v.paths, v.prefs); err != nil {
					v.err = err.Error()
					return
				}
				v.flash = "approval popup timeout → " + pick.value
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
				v.flash = "admin idle timeout → " + pick.value + "  (effective on next `dop admin login`)"
				return
			}
		}
	case settingRowHarness:
		v.prefs.Harness = pick.value
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.err = err.Error()
			return
		}
		v.flash = "harness → " + userprefs.HarnessLabel(pick.value)
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
		return intToStr(secs/60) + " min"
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

func (v *settingsView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Settings") + "\n\n")

	switch v.mode {
	case settingsModeCustom:
		b.WriteString(v.viewCustom())
	case settingsModePicker:
		b.WriteString(v.viewPicker())
	default:
		b.WriteString(v.viewList())
	}

	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash) + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	return b.String()
}

func (v *settingsView) viewList() string {
	var b strings.Builder
	rows := []struct {
		label string
		value string
		hint  string
	}{
		{"Agent key backend", v.rowValueFileKeys(), "default (SE / ed25519) vs extractable file-backed P-256"},
		{"Approval popup timeout", v.rowValueApprovalTimeout(), "how long the osascript dialog waits before upgrading to tunnel+phone"},
		{"Admin session idle timeout", v.rowValueAdminIdleTTL(), "how long the admin daemon stays unlocked without activity"},
		{"Harness", v.rowValueHarness(), "which session env var DOP consults for the trust-context cache"},
	}
	for i, r := range rows {
		prefix := "    "
		labelSt := mutedSt
		if i == v.rowCursor {
			prefix = "  " + cursorSt.Render("➤ ")
			labelSt = cursorSt
		}
		b.WriteString(prefix + labelSt.Render(r.label) + "  " + okSt.Render("["+r.value+"]") + "\n")
		if i == v.rowCursor {
			b.WriteString("      " + mutedSt.Render(r.hint) + "\n")
		}
	}
	b.WriteString("\n" + helpSt.Render("↑↓ move · enter change · esc back"))
	return b.String()
}

func (v *settingsView) viewPicker() string {
	var b strings.Builder
	title := []string{"Agent key backend", "Approval popup timeout", "Admin session idle timeout", "Harness"}[v.pickerRow]
	b.WriteString(cursorSt.Render(title) + "\n\n")
	for i, c := range v.choicesFor(v.pickerRow) {
		prefix := "    "
		label := c.label
		if i == v.pickerCursor {
			prefix = "  " + cursorSt.Render("➤ ")
			label = cursorSt.Render(label)
		}
		b.WriteString(prefix + label + "\n")
	}
	b.WriteString("\n" + helpSt.Render("↑↓ move · enter pick · esc back to settings"))
	return b.String()
}

func (v *settingsView) viewCustom() string {
	var b strings.Builder
	b.WriteString(cursorSt.Render("Admin session idle timeout — custom") + "\n\n")
	b.WriteString(mutedSt.Render("Examples:  15m   2h   24h   90m   never") + "\n")
	b.WriteString(mutedSt.Render("Minimum: 1 minute. Enter `never` for no timeout (manual logout only).") + "\n\n")
	b.WriteString("Duration: " + v.customBuf.String() + cursorSt.Render("▎") + "\n")
	if v.customErr != "" {
		b.WriteString("\n" + failSt.Render(v.customErr) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter commit · esc back to presets"))
	return b.String()
}

func (v *settingsView) rowValueFileKeys() string {
	if v.prefs.AllowFileKeys {
		return "yes"
	}
	return "no"
}
func (v *settingsView) rowValueApprovalTimeout() string {
	s := v.prefs.ApprovalPopupTimeoutSeconds
	if s == 0 {
		s = userprefs.ApprovalTimeoutDefaultSeconds
	}
	return humanDur(s)
}
func (v *settingsView) rowValueAdminIdleTTL() string {
	return userprefs.AdminIdleTTLLabel(v.prefs.AdminIdleTTLSeconds)
}
func (v *settingsView) rowValueHarness() string {
	if v.prefs.Harness == "" {
		return "unset"
	}
	return userprefs.HarnessLabel(v.prefs.Harness)
}
