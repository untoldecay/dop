//go:build darwin && cgo

package main

import "runtime"

// The native window must run on the process's main thread; pinning the
// main goroutine there costs the other commands nothing.
func init() { runtime.LockOSThread() }
