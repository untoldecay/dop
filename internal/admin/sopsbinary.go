package admin

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"filippo.io/age"
)

// Vault encryption runs in-process (internal/sopsfile, dop-bki). The
// `sops` binary path stays reachable with DOP_SOPS_BINARY=1 during the
// transition, as a fallback if a vault ever fails to open in-process.
func useSopsBinary() bool { return os.Getenv("DOP_SOPS_BINARY") == "1" }

func sopsBinaryDecrypt(vaultPath string, id *age.X25519Identity) ([]byte, error) {
	cmd := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", vaultPath)
	// The key goes to the child only, never to dop's own environment.
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+id.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops decrypt: %s (%v)", stderr.String(), err)
	}
	return stdout.Bytes(), nil
}

func sopsBinaryEncrypt(vaultPath string, plaintext []byte, recipients string) error {
	// Stage plaintext next to the vault so sops picks up the vault's
	// .sops.yaml; --age is explicit, so path-based config quirks don't
	// matter.
	tmp, err := os.CreateTemp(filepath.Dir(vaultPath), ".dop-encrypt-*.yaml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	cmd := exec.Command("sops", "--encrypt",
		"--age", recipients,
		"--input-type", "yaml", "--output-type", "yaml",
		"--output", vaultPath, tmpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops encrypt: %s (%v)", stderr.String(), err)
	}
	return nil
}

// writeFileAtomic writes via a temp file + rename, so a crash never
// leaves a half-written vault.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dop-vault-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
