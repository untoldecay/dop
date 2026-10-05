package tui

import "testing"

// TestTextField_CaretInsert covers the show-stopper Cam flagged:
// pre-filling a field with existing text and editing in the middle.
// Pre-rc6f strings.Builder behaviour was append-at-end; this verifies
// insertion lands at the cursor's position.
func TestTextField_CaretInsert(t *testing.T) {
	var f textField
	f.SetString("my description")
	// SetString parks cursor at end.
	if f.cursor != len([]rune("my description")) {
		t.Fatalf("cursor after SetString = %d, want %d", f.cursor, len([]rune("my description")))
	}
	// Move cursor to position 3 ("my |description").
	for i := 0; i < 11; i++ {
		f.MoveLeft()
	}
	if f.cursor != 3 {
		t.Fatalf("cursor after 11×MoveLeft = %d, want 3", f.cursor)
	}
	f.InsertString("new ")
	if got := f.String(); got != "my new description" {
		t.Fatalf("insert at cursor: got %q, want %q", got, "my new description")
	}
	// Cursor should now be past the inserted substring.
	if f.cursor != 7 {
		t.Fatalf("cursor after insert = %d, want 7", f.cursor)
	}
}

func TestTextField_Backspace(t *testing.T) {
	var f textField
	f.SetString("hello")
	f.MoveLeft() // cursor between l and o
	f.MoveLeft() // cursor between l and l
	f.Backspace()
	if got := f.String(); got != "helo" {
		t.Fatalf("backspace mid: got %q, want %q", got, "helo")
	}
	if f.cursor != 2 {
		t.Fatalf("cursor after backspace = %d, want 2", f.cursor)
	}
}

func TestTextField_BackspaceAtStart(t *testing.T) {
	var f textField
	f.SetString("hi")
	f.MoveHome()
	if f.Backspace() {
		t.Fatal("Backspace at start should return false")
	}
	if got := f.String(); got != "hi" {
		t.Fatalf("after no-op backspace: got %q, want %q", got, "hi")
	}
}

func TestTextField_Delete(t *testing.T) {
	var f textField
	f.SetString("hello")
	f.MoveHome()
	f.Delete()
	if got := f.String(); got != "ello" {
		t.Fatalf("delete at head: got %q, want %q", got, "ello")
	}
	if f.cursor != 0 {
		t.Fatalf("cursor after delete = %d, want 0", f.cursor)
	}
}

func TestTextField_Split(t *testing.T) {
	var f textField
	f.SetString("abcdef")
	f.MoveLeft()
	f.MoveLeft() // cursor between d and e
	before, after := f.Split()
	if before != "abcd" || after != "ef" {
		t.Fatalf("Split: got (%q,%q), want (%q,%q)", before, after, "abcd", "ef")
	}
}

func TestTextField_SplitMasked(t *testing.T) {
	var f textField
	f.SetString("secret")
	f.MoveHome()
	f.MoveRight()
	f.MoveRight()
	before, after := f.SplitMasked("•")
	if before != "••" || after != "••••" {
		t.Fatalf("SplitMasked: got (%q,%q)", before, after)
	}
}

// TestTextField_HandleKey verifies the key dispatcher consumes the
// right events so views can keep their switch for tab/enter/esc etc.
func TestTextField_HandleKey(t *testing.T) {
	var f textField
	f.SetString("abc")
	// typing at end
	if !f.handleKey("x", []rune("x")) {
		t.Fatal("handleKey rune not consumed")
	}
	if got := f.String(); got != "abcx" {
		t.Fatalf("after typing: got %q, want %q", got, "abcx")
	}
	// left + delete
	f.handleKey("left", nil)
	f.handleKey("left", nil)
	f.handleKey("delete", nil)
	if got := f.String(); got != "abx" {
		t.Fatalf("after delete: got %q, want %q", got, "abx")
	}
	// tab/enter/esc should NOT be consumed by the field.
	if f.handleKey("tab", nil) || f.handleKey("enter", nil) || f.handleKey("esc", nil) {
		t.Fatal("navigation keys should fall through, not be consumed")
	}
}

// TestTextField_UTF8 covers rune-safe editing — the strings.Builder
// path would have split a multi-byte rune on backspace.
func TestTextField_UTF8(t *testing.T) {
	var f textField
	f.SetString("café") // "café"
	if f.Len() != 4 {
		t.Fatalf("Len = %d, want 4 (rune count)", f.Len())
	}
	f.Backspace()
	if got := f.String(); got != "caf" {
		t.Fatalf("backspace on multi-byte: got %q, want %q", got, "caf")
	}
	f.InsertString("é")
	if got := f.String(); got != "café" {
		t.Fatalf("re-insert multi-byte: got %q, want %q", got, "café")
	}
}
