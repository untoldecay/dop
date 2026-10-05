// textField — editable text buffer with an in-field caret.
//
// Prior to v1.14.0-rc6f, text inputs across the TUI stored their value
// in a plain strings.Builder: typing appended at the end, backspace
// removed the last rune, and left/right/home/end did nothing. For a
// field pre-filled with existing content (integration edit · desc,
// name, slot, projects, tags) the "caret stuck at end" effectively
// forced operators to backspace everything they wanted to change —
// Cam flagged this as a show-stopper on the edit path.
//
// textField fixes that with the minimum surface required: a rune
// slice + a cursor index + the five operations a TUI field actually
// uses (insert, backspace, delete, move, home/end). The cursor is a
// rune index into the slice; byte-indexing is never exposed.

package tui

import "strings"

// textField is a minimal editable text buffer with cursor support.
// Zero value is a valid empty field.
type textField struct {
	runes  []rune
	cursor int // 0..len(runes), inclusive
}

// String returns the full text.
func (f *textField) String() string {
	return string(f.runes)
}

// Len returns the rune count — matches strings.Builder.Len() closely
// enough for the usual "is this field empty?" check.
func (f *textField) Len() int {
	return len(f.runes)
}

// Reset empties the field and parks the cursor at position 0.
func (f *textField) Reset() {
	f.runes = f.runes[:0]
	f.cursor = 0
}

// SetString replaces the entire content and moves the cursor to the
// end — this is how we seed an edit form from existing state.
func (f *textField) SetString(s string) {
	f.runes = []rune(s)
	f.cursor = len(f.runes)
}

// InsertRunes inserts the given runes at the cursor and advances the
// cursor past them. Allocation-light: appends then shifts in place.
func (f *textField) InsertRunes(r []rune) {
	if len(r) == 0 {
		return
	}
	// Grow with zero-value runes at the end.
	f.runes = append(f.runes, make([]rune, len(r))...)
	// Shift the tail right by len(r).
	copy(f.runes[f.cursor+len(r):], f.runes[f.cursor:len(f.runes)-len(r)])
	// Drop the new runes into the gap.
	copy(f.runes[f.cursor:], r)
	f.cursor += len(r)
}

// InsertString is a convenience over InsertRunes for the common
// "the key handler produced a string" case.
func (f *textField) InsertString(s string) {
	f.InsertRunes([]rune(s))
}

// Backspace removes the rune before the cursor (if any) and moves the
// cursor left by one. No-op at the start of the field.
func (f *textField) Backspace() bool {
	if f.cursor == 0 {
		return false
	}
	f.runes = append(f.runes[:f.cursor-1], f.runes[f.cursor:]...)
	f.cursor--
	return true
}

// Delete removes the rune at the cursor (if any). The cursor stays
// put. No-op at the end of the field.
func (f *textField) Delete() bool {
	if f.cursor >= len(f.runes) {
		return false
	}
	f.runes = append(f.runes[:f.cursor], f.runes[f.cursor+1:]...)
	return true
}

// MoveLeft moves the cursor one rune to the left. No-op at the start.
func (f *textField) MoveLeft() {
	if f.cursor > 0 {
		f.cursor--
	}
}

// MoveRight moves the cursor one rune to the right. No-op at the end.
func (f *textField) MoveRight() {
	if f.cursor < len(f.runes) {
		f.cursor++
	}
}

// MoveHome parks the cursor at position 0.
func (f *textField) MoveHome() { f.cursor = 0 }

// MoveEnd parks the cursor after the last rune.
func (f *textField) MoveEnd() { f.cursor = len(f.runes) }

// Split returns the text before and after the cursor as separate
// strings — view code uses this to insert the caret glyph at the
// correct visual position.
func (f *textField) Split() (before, after string) {
	return string(f.runes[:f.cursor]), string(f.runes[f.cursor:])
}

// SplitMasked is like Split but replaces every rune with the mask
// character — used for password-style fields where the cursor still
// needs to render at a position within the masked bullets.
func (f *textField) SplitMasked(mask string) (before, after string) {
	return strings.Repeat(mask, f.cursor), strings.Repeat(mask, len(f.runes)-f.cursor)
}

// handleKey is the shared "give me a key string, I'll do the field
// edit" entry point. Returns true if the key was consumed (caller
// should early-return) and false if it falls through to the view's
// own navigation logic (tab, enter, esc, etc).
//
// Keys consumed: left, right, home, end, backspace, delete, and
// any rune key (via the runes argument).
func (f *textField) handleKey(key string, runes []rune) bool {
	switch key {
	case "left":
		f.MoveLeft()
		return true
	case "right":
		f.MoveRight()
		return true
	case "home", "ctrl+a":
		f.MoveHome()
		return true
	case "end", "ctrl+e":
		f.MoveEnd()
		return true
	case "backspace":
		f.Backspace()
		return true
	case "delete", "ctrl+d":
		f.Delete()
		return true
	}
	if len(runes) > 0 {
		f.InsertRunes(runes)
		return true
	}
	return false
}
