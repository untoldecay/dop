// Package agentrules is the short block of standing rules an agent
// must carry in its always-on instructions (a skill loads on demand;
// prohibitions cannot). dop prints it at claim time, the agent
// acknowledges it with `dop skill rules --ack`, `dop exec` nudges while
// it is missing, and the operator sees per bearer whether it happened.
package agentrules

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fray/dop/internal/config"
)

//go:embed rules.md
var Text string

// Version changes when the rules change; an older ack still counts
// (the point is that the agent carries the block, not its wording).
const Version = 1

// Ack is what an agent host records: when, which agent keys live here.
type Ack struct {
	Version   int       `json:"version"`
	Host      string    `json:"host"`
	AckedAt   time.Time `json:"acked_at"`
	LookupIDs []string  `json:"lookup_ids"`
}

func localPath(paths *config.Paths) string { return filepath.Join(paths.Root, "agent-rules.ack") }
func nudgePath(paths *config.Paths) string { return filepath.Join(paths.Root, "agent-rules.nudged") }

// VaultDir is where acks travel to the admin: one file per agent key
// in the vault repo, pushed by the agent host when it can. (rc13 wrote
// one file per host; three agents on one server overwrote each other.)
func VaultDir(paths *config.Paths) string { return filepath.Join(paths.Vault, "agent-rules") }

// LocalKeys lists the lookup ids of the agent keys on this host.
func LocalKeys(paths *config.Paths) []string {
	var ids []string
	for _, ext := range []string{".key", ".p256", ".se"} {
		m, _ := filepath.Glob(filepath.Join(paths.Root, "agent-keys", "*"+ext))
		for _, p := range m {
			ids = append(ids, strings.TrimSuffix(filepath.Base(p), ext))
		}
	}
	return ids
}

// Record writes the local ack and, when a vault repo is present, one
// entry per agent key of this install in it. It returns the entries'
// directory relative to the vault ("" when none) so the caller can
// commit and push.
func Record(paths *config.Paths) (rel string, err error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "agent"
	}
	a := Ack{Version: Version, Host: host, AckedAt: time.Now().UTC().Truncate(time.Second), LookupIDs: LocalKeys(paths)}
	blob, _ := json.MarshalIndent(a, "", "  ")
	blob = append(blob, '\n')
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(localPath(paths), blob, 0o600); err != nil {
		return "", err
	}
	_ = os.Remove(nudgePath(paths))
	if _, serr := os.Stat(filepath.Join(paths.Vault, ".git")); serr != nil {
		return "", nil
	}
	if err := os.MkdirAll(VaultDir(paths), 0o755); err != nil {
		return "", err
	}
	for _, id := range a.LookupIDs {
		one := a
		one.LookupIDs = []string{id}
		b, _ := json.MarshalIndent(one, "", "  ")
		if err := os.WriteFile(filepath.Join(VaultDir(paths), safe(id)+".json"), append(b, '\n'), 0o644); err != nil {
			return "", err
		}
	}
	return "agent-rules", nil
}

// AckedHere says whether this host acknowledged the rules.
func AckedHere(paths *config.Paths) bool {
	_, err := os.Stat(localPath(paths))
	return err == nil
}

// NudgeDue is true at most once an hour while this host has not
// acknowledged; it records the nudge.
func NudgeDue(paths *config.Paths) bool {
	if AckedHere(paths) {
		return false
	}
	if st, err := os.Stat(nudgePath(paths)); err == nil && time.Since(st.ModTime()) < time.Hour {
		return false
	}
	_ = os.MkdirAll(paths.Root, 0o700)
	_ = os.WriteFile(nudgePath(paths), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	return true
}

// Acks maps each acknowledged agent-key lookup id to its ack (host,
// time): this host's ack plus every entry in the vault repo.
func Acks(paths *config.Paths) map[string]Ack {
	out := map[string]Ack{}
	add := func(p string) {
		blob, err := os.ReadFile(p)
		if err != nil {
			return
		}
		var a Ack
		if json.Unmarshal(blob, &a) != nil {
			return
		}
		for _, id := range a.LookupIDs {
			if prev, ok := out[id]; !ok || a.AckedAt.After(prev.AckedAt) {
				out[id] = a
			}
		}
	}
	add(localPath(paths))
	m, _ := filepath.Glob(filepath.Join(VaultDir(paths), "*.json"))
	for _, p := range m {
		add(p)
	}
	return out
}

// Confirmed is the set of acknowledged agent-key lookup ids.
func Confirmed(paths *config.Paths) map[string]bool {
	out := map[string]bool{}
	for id := range Acks(paths) {
		out[id] = true
	}
	return out
}

// Detail is the bearer detail row: where and when the agent
// acknowledged, or what is missing.
func Detail(acks map[string]Ack, lookupID string, bound bool) string {
	if !bound {
		return "no agent key yet — shown once the bearer is claimed"
	}
	a, ok := acks[lookupID]
	if !ok {
		return "not confirmed — the agent has not run dop skill rules --ack"
	}
	return "confirmed by " + a.Host + " · " + a.AckedAt.Local().Format("2006-01-02 15:04")
}

// Status is the operator-facing word for one bearer: "" when the
// bearer is not bound to an agent key, else "confirmed" / "unconfirmed".
func Status(confirmed map[string]bool, lookupID string, bound bool) string {
	switch {
	case !bound:
		return ""
	case confirmed[lookupID]:
		return "confirmed"
	}
	return "unconfirmed"
}

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
}
