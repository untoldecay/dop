package agentkey

import "crypto/sha256"

// sha256Sum wraps crypto/sha256.Sum256 so callers keep a tight
// signature-signing implementation without a top-level import for
// something this trivial.
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
