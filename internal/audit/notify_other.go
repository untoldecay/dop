//go:build !darwin

package audit

// Notify is a no-op on non-Darwin platforms. A future Linux
// implementation could shell out to `notify-send`.
func Notify(_ Event) {}
