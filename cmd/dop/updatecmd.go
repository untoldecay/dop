// `dop update` — v1.14.0-rc7f. In-place updater that fetches releases
// from GitHub, verifies the checksum, and atomic-renames the new
// binary over the installed one (keeping the previous for rollback).
//
// No prompts by default: `dop update` is an explicit command, so
// invoking it IS the "yes." Exception: cross-major jumps or
// downgrades require typing CONFIRM, matching the dop-admin-reset
// discipline.
//
// Install location strategy:
//   - If the currently-running binary location is user-writable, write
//     back there.
//   - If not, migrate to ~/.local/bin/dop and print a one-liner for
//     the operator to manually remove the old (sudo-required) location.
//
// Rollback: before replacing the binary, copy the current one to
// ~/.local/share/dop/old-versions/dop-<version>. Keep the last 3.
// `dop update --rollback` restores the most recently stored prior
// version.

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/version"
)

const (
	updateGitHubOwner = "untoldecay"
	updateGitHubRepo  = "dop"
	updateUserAgent   = "dop-update/1"
	updateKeepHistory = 3 // last 3 old versions in ~/.local/share/dop/old-versions/
)

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type release struct {
	TagName     string         `json:"tag_name"`
	Prerelease  bool           `json:"prerelease"`
	Draft       bool           `json:"draft"`
	PublishedAt string         `json:"published_at"`
	Body        string         `json:"body"`
	Assets      []releaseAsset `json:"assets"`
}

func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fs.Bool("check-only", false, "print installed vs latest, do not touch the filesystem")
	channel := fs.String("channel", "", "override the persisted update channel for this invocation (stable | dev)")
	targetVersion := fs.String("version", "", "install this specific release tag (downgrade allowed; prompts for confirmation)")
	rollback := fs.Bool("rollback", false, "revert to the most recently stored previous version (see ~/.local/share/dop/old-versions/)")
	_ = fs.Parse(args)

	if *rollback {
		return runUpdateRollback()
	}

	// Resolve effective channel. Persisted pref lands in rc7h; for now
	// default to stable, with CLI override via --channel.
	ch := strings.ToLower(strings.TrimSpace(*channel))
	if ch == "" {
		ch = "stable"
	}
	if ch != "stable" && ch != "dev" {
		fmt.Fprintf(os.Stderr, "dop update: unknown channel %q (want stable or dev)\n", ch)
		return 2
	}

	// Fetch target release metadata.
	var rel *release
	var err error
	if *targetVersion != "" {
		rel, err = fetchReleaseByTag(*targetVersion)
	} else {
		rel, err = fetchLatestRelease(ch)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop update: %v\n", err)
		return 1
	}
	installed := version.Version

	// Check-only: print and exit.
	if *checkOnly {
		fmt.Fprintf(os.Stderr, "Installed: %s\n", installed)
		fmt.Fprintf(os.Stderr, "Latest (%s channel): %s", ch, rel.TagName)
		if rel.PublishedAt != "" {
			fmt.Fprintf(os.Stderr, "  (published %s)", rel.PublishedAt)
		}
		fmt.Fprintln(os.Stderr)
		if installed == rel.TagName {
			fmt.Fprintln(os.Stderr, "Already on latest.")
			return 0
		}
		fmt.Fprintln(os.Stderr, "Run `dop update` to install.")
		return 0
	}

	// Noop if already on the requested tag (unless --version was passed
	// — explicit version always proceeds, since the operator might be
	// re-installing to recover from a corrupted binary).
	if installed == rel.TagName && *targetVersion == "" {
		fmt.Fprintf(os.Stderr, "dop update: already on %s (channel: %s)\n", installed, ch)
		return 0
	}

	// Downgrade or cross-major → require typed confirmation. "dev" rc
	// jumps between tags on the same release line are NOT prompted —
	// that's the whole point of the channel.
	if needsConfirmation(installed, rel.TagName) {
		if !confirmTyped(fmt.Sprintf("You're about to switch %s → %s. Type CONFIRM to proceed: ", installed, rel.TagName), "CONFIRM") {
			fmt.Fprintln(os.Stderr, "dop update: aborted (no confirmation).")
			return 1
		}
	}

	// Download + verify + install.
	if err := performUpdate(rel); err != nil {
		fmt.Fprintf(os.Stderr, "dop update: %v\n", err)
		return 1
	}
	return 0
}

func runUpdateRollback() int {
	store, err := oldVersionsDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop update --rollback: %v\n", err)
		return 1
	}
	entries, err := os.ReadDir(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop update --rollback: no stored versions at %s\n", store)
		return 1
	}
	// Sort by mtime desc; pick the newest that isn't the running binary.
	type stored struct {
		path  string
		mtime time.Time
	}
	var all []stored
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, stored{path: filepath.Join(store, e.Name()), mtime: info.ModTime()})
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "dop update --rollback: no stored versions yet (update at least once first)")
		return 1
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mtime.After(all[j].mtime) })
	src := all[0].path
	runningBin, _ := os.Executable()
	// Edge case: current binary happens to match the newest stored.
	// Fall back to the next one if available.
	if filepath.Base(src) == "dop-"+version.Version && len(all) > 1 {
		src = all[1].path
	}
	fmt.Fprintf(os.Stderr, "dop update --rollback: restoring %s → %s\n", filepath.Base(src), runningBin)
	if err := atomicReplace(src, runningBin, true); err != nil {
		fmt.Fprintf(os.Stderr, "dop update --rollback: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "  ✓ done. Re-run `dop version` to confirm.")
	return 0
}

// fetchLatestRelease hits the GitHub API and returns the newest
// release for the given channel. stable → /releases/latest (excludes
// prereleases); dev → /releases (newest index, including prereleases).
func fetchLatestRelease(channel string) (*release, error) {
	switch channel {
	case "stable":
		return githubGetJSON[release](fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", updateGitHubOwner, updateGitHubRepo))
	case "dev":
		list, err := githubGetJSON[[]release](fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=30", updateGitHubOwner, updateGitHubRepo))
		if err != nil {
			return nil, err
		}
		// GitHub's /releases endpoint returns results in tag-name
		// (lexical) order, NOT publication-time order. For a release
		// line like v1.14.0-rc7e / v1.14.0-rc6m, lexical puts rc7e
		// first even if rc6m was published later. Sort manually by
		// published_at desc so "dev latest" means "most recent."
		nonDraft := make([]release, 0, len(*list))
		for _, r := range *list {
			if !r.Draft {
				nonDraft = append(nonDraft, r)
			}
		}
		if len(nonDraft) == 0 {
			return nil, fmt.Errorf("no releases found on dev channel")
		}
		sort.Slice(nonDraft, func(i, j int) bool {
			return nonDraft[i].PublishedAt > nonDraft[j].PublishedAt
		})
		top := nonDraft[0]
		return &top, nil
	default:
		return nil, fmt.Errorf("unknown channel %q", channel)
	}
}

func fetchReleaseByTag(tag string) (*release, error) {
	// Allow passing "v1.14.0" or "1.14.0" — the API wants the exact
	// tag string, so leave it as-is; just trim obvious noise.
	tag = strings.TrimSpace(tag)
	return githubGetJSON[release](fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", updateGitHubOwner, updateGitHubRepo, tag))
}

func githubGetJSON[T any](url string) (*T, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updateUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	return &out, nil
}

// needsConfirmation returns true for scary jumps that merit a typed
// CONFIRM: downgrades on the same channel, or any cross-major move.
// Simple string checks — we're not shipping a semver parser just for
// this. "dev" rc→rc jumps within the same minor line never qualify.
func needsConfirmation(from, to string) bool {
	if from == "dev" {
		return false // local dev build; always safe to replace
	}
	fromMajor := extractMajorMinor(from)
	toMajor := extractMajorMinor(to)
	if fromMajor != "" && toMajor != "" && fromMajor != toMajor {
		return true
	}
	// Downgrade heuristic: lexically-smaller tag on the same major
	// line probably means moving backward.
	if from > to {
		return true
	}
	return false
}

// extractMajorMinor returns "v1.14" from "v1.14.0-rc6m-smoke". Empty
// string if the tag doesn't look parseable.
func extractMajorMinor(tag string) string {
	tag = strings.TrimPrefix(tag, "v")
	parts := strings.SplitN(tag, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return "v" + parts[0] + "." + parts[1]
}

// confirmTyped prompts via stderr/stdin and returns true iff the user
// types the expected string exactly.
func confirmTyped(prompt, expect string) bool {
	fmt.Fprint(os.Stderr, prompt)
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		return false
	}
	return strings.TrimSpace(line) == expect
}

// performUpdate drives the download → verify → store-old → install
// pipeline. Nothing is touched on disk until the checksum verifies
// and the new binary is executable.
func performUpdate(rel *release) error {
	assetName := platformAssetName(rel.TagName)
	var assetURL string
	for _, a := range rel.Assets {
		if a.Name == assetName {
			assetURL = a.URL
			break
		}
	}
	if assetURL == "" {
		return fmt.Errorf("no asset %q in release %s (release may not have published artifacts yet)", assetName, rel.TagName)
	}
	var checksumsURL string
	for _, a := range rel.Assets {
		if a.Name == "checksums.txt" {
			checksumsURL = a.URL
			break
		}
	}

	tmpDir, err := os.MkdirTemp("", "dop-update-*")
	if err != nil {
		return fmt.Errorf("tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tgzPath := filepath.Join(tmpDir, assetName)
	fmt.Fprintf(os.Stderr, "dop update: downloading %s\n", assetName)
	if err := downloadTo(assetURL, tgzPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if checksumsURL != "" {
		fmt.Fprintln(os.Stderr, "dop update: verifying checksum")
		if err := verifyChecksum(checksumsURL, tgzPath, assetName); err != nil {
			return fmt.Errorf("checksum: %w", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "dop update: WARNING no checksums.txt in release — skipping verification")
	}
	fmt.Fprintln(os.Stderr, "dop update: extracting")
	newBin := filepath.Join(tmpDir, "dop")
	if err := extractDopBinary(tgzPath, newBin); err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	if err := os.Chmod(newBin, 0o755); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	// Store the current binary to the old-versions cache (best-effort;
	// a stat/read failure doesn't block the swap).
	runningBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	targetBin, migrated, migrateHint, err := resolveTargetBin(runningBin)
	if err != nil {
		return err
	}
	if _, err := os.Stat(runningBin); err == nil {
		if store, err := oldVersionsDir(); err == nil {
			_ = os.MkdirAll(store, 0o700)
			slot := filepath.Join(store, "dop-"+version.Version)
			if err := copyFile(runningBin, slot); err == nil {
				_ = pruneOldVersions(store, updateKeepHistory)
				fmt.Fprintf(os.Stderr, "dop update: stored prior version at %s\n", slot)
			} else {
				fmt.Fprintf(os.Stderr, "dop update: warn: could not store prior version: %v\n", err)
			}
		}
	}

	// Atomic rename into targetBin.
	if err := atomicReplace(newBin, targetBin, migrated); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "dop update: installed %s at %s\n", rel.TagName, targetBin)
	if migrateHint != "" {
		fmt.Fprintln(os.Stderr, migrateHint)
	}
	fmt.Fprintln(os.Stderr, "  Re-run any `dop` command to use the new version.")
	return nil
}

// resolveTargetBin returns where to install the new binary, whether a
// migration occurred (old path was not writable), and a hint for the
// operator to manually clean up the stale location when migrated.
func resolveTargetBin(runningBin string) (string, bool, string, error) {
	// Writable test: open-with-write on the DIRECTORY (not the file,
	// which is held open by this process). If the dir is writable, we
	// can replace the binary in place via rename.
	parent := filepath.Dir(runningBin)
	if canWrite(parent) {
		return runningBin, false, "", nil
	}
	// Migrate to ~/.local/bin/dop.
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, "", fmt.Errorf("resolve home: %w", err)
	}
	localBinDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(localBinDir, 0o755); err != nil {
		return "", false, "", fmt.Errorf("mkdir %s: %w", localBinDir, err)
	}
	target := filepath.Join(localBinDir, "dop")
	hint := fmt.Sprintf("  Migrated install from %s → %s.\n"+
		"  The old location is still on disk and needs sudo to remove. Run:\n"+
		"    sudo rm %s && hash -r\n"+
		"  Ensure %s is on your $PATH (it already is by default on most shells).",
		runningBin, target, runningBin, localBinDir)
	return target, true, hint, nil
}

// canWrite probes a directory for writability without actually
// creating a persistent file.
func canWrite(dir string) bool {
	f, err := os.CreateTemp(dir, ".dop-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// atomicReplace moves src over target. If migrated is true, src is a
// different-filesystem path and we fall back to copy+rename within
// target's directory.
func atomicReplace(src, target string, migrated bool) error {
	// Rename works if src and target are on the same filesystem.
	// Fall back to copy+rename otherwise.
	if err := os.Rename(src, target); err == nil {
		return nil
	}
	// Copy to a sibling of target, then rename over target.
	tmp := target + ".new"
	if err := copyFile(src, tmp); err != nil {
		return fmt.Errorf("stage new binary: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("chmod staged: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename over target %s: %w", target, err)
	}
	_ = migrated
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func downloadTo(url, dst string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", updateUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func verifyChecksum(checksumsURL, tgzPath, assetName string) error {
	resp, err := http.Get(checksumsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET checksums: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// Format: <sha256> <filename>
	var want string
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		if fields[1] == assetName {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("no checksum for %s in checksums.txt", assetName)
	}
	f, err := os.Open(tgzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum mismatch: want %s, got %s", want, got)
	}
	return nil
}

// extractDopBinary pulls the "dop" entry out of the tar.gz into dst.
// Ignores other entries (dop-credential-git, LICENSE, README).
func extractDopBinary(tgzPath, dst string) error {
	f, err := os.Open(tgzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(h.Name) != "dop" {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
		return nil
	}
	return fmt.Errorf("tarball did not contain a `dop` binary")
}

// platformAssetName returns the goreleaser-shaped asset name for the
// current OS/arch and the given tag. Example:
// "dop_1.14.0-rc6m-smoke_darwin_arm64.tar.gz"
func platformAssetName(tag string) string {
	v := strings.TrimPrefix(tag, "v")
	osStr := runtime.GOOS
	arch := runtime.GOARCH
	// goreleaser uses "amd64" (same as GOARCH).
	return fmt.Sprintf("dop_%s_%s_%s.tar.gz", v, osStr, arch)
}

func oldVersionsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "dop", "old-versions"), nil
}

// pruneOldVersions removes everything but the most-recent keep.
func pruneOldVersions(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type stored struct {
		path  string
		mtime time.Time
	}
	var all []stored
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, stored{path: filepath.Join(dir, e.Name()), mtime: info.ModTime()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mtime.After(all[j].mtime) })
	for i := keep; i < len(all); i++ {
		_ = os.Remove(all[i].path)
	}
	return nil
}
