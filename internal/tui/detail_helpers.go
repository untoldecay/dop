// v1.13.0-rc18 — shared helpers for detail panes. Pattern first
// extracted from integrationMetaBlock (rc17) + viewDetail (rc17.1).
// Now shared across grantListView and listView (bearers) so the three
// detail panes render with identical shape: 2-space indent, label
// padded for alignment, "only non-empty by default" row rendering.
//
// If a future detail pane wants a different shape, add a sibling
// helper rather than overloading these — the point is consistency
// across all three canonical list views.

package tui

import (
	"fmt"
	"strings"
)

// kvLine returns one `  label: value\n` row for a detail pane.
// Returns the empty string when value is blank, so callers can emit
// rows unconditionally and let the helper filter.
//
// labelWidth is the fixed left-column width for alignment. Pass the
// longest label length in the pane. 0 disables padding.
func kvLine(label, value string, labelWidth int) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if labelWidth > 0 {
		label = fmt.Sprintf("%-*s", labelWidth, label)
	}
	return "  " + label + ": " + value + "\n"
}

// kvLineAlways is kvLine's variant that always renders the row, even
// when value is empty — substituting a muted placeholder. Used when
// the absence of a field is itself the signal (e.g. "projects: (none)").
func kvLineAlways(label, value, emptyPlaceholder string, labelWidth int) string {
	if strings.TrimSpace(value) == "" {
		value = mutedSt.Render(emptyPlaceholder)
	}
	if labelWidth > 0 {
		label = fmt.Sprintf("%-*s", labelWidth, label)
	}
	return "  " + label + ": " + value + "\n"
}
