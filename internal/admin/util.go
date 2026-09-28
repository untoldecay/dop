package admin

import "encoding/base64"

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
