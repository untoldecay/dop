//go:build !darwin || !cgo

package approvalwindow

// Run is unavailable here; the caller falls back to the system alert.
func Run(Request) (Result, error) { return Result{}, ErrUnsupported }
