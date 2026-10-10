//go:build darwin && !cgo

package agentkey

import "errors"

// ProbeSecureEnclave: the Secure Enclave bridge needs cgo.
func ProbeSecureEnclave() error {
	return errors.New("built without cgo — no Secure Enclave bridge")
}
