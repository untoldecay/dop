// Package vaultgit runs the vault repo's git operations in-process with
// go-git (dop-bki), so dop works on a machine without git installed.
//
// It covers exactly what dop does with the vault repo — clone, fetch,
// fast-forward, ahead/behind counts, merge base, read a file at a
// commit, reset, add, commit, a two-parent "ours" merge commit, push,
// log. dop never asks git to merge file contents: diverged vaults are
// merged on the decrypted plaintext (vault.Merge), and git only records
// the result.
package vaultgit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// ErrNotFastForward: the local branch and the remote have diverged.
var ErrNotFastForward = errors.New("not possible to fast-forward")

// ErrNothingToCommit mirrors `git commit` exiting 1 on a clean tree.
var ErrNothingToCommit = errors.New("nothing to commit, working tree clean")

const remoteName = "origin"

// InitBare creates an empty bare repository whose HEAD is main.
func InitBare(path string) error {
	_, err := git.PlainInitWithOptions(path, &git.PlainInitOptions{
		Bare:        true,
		InitOptions: git.InitOptions{DefaultBranch: plumbing.Main},
	})
	return err
}

// Clone clones url into dest. An empty remote (a vault repo nobody has
// pushed to yet) gives an empty checkout tracking origin/main, the way
// `git clone` does.
func Clone(url, dest string) error {
	err := withAuth(url, func(a transport.AuthMethod) error {
		_, err := git.PlainClone(dest, false, &git.CloneOptions{URL: url, Auth: a})
		if err != nil {
			_ = os.RemoveAll(dest)
		}
		return err
	})
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return initEmptyClone(url, dest)
	}
	return err
}

func initEmptyClone(url, dest string) error {
	r, err := git.PlainInitWithOptions(dest, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.Main},
	})
	if err != nil {
		return err
	}
	if _, err := r.CreateRemote(&gitconfig.RemoteConfig{Name: remoteName, URLs: []string{url}}); err != nil {
		return err
	}
	return r.CreateBranch(&gitconfig.Branch{Name: "main", Remote: remoteName, Merge: plumbing.NewBranchReferenceName("main")})
}

// Repo is an open vault checkout.
type Repo struct {
	dir string
	r   *git.Repository
}

// Open opens the checkout at dir.
func Open(dir string) (*Repo, error) {
	r, err := git.PlainOpen(dir)
	if err != nil {
		return nil, err
	}
	return &Repo{dir: dir, r: r}, nil
}

// RemoteURL is origin's URL, or "".
func (g *Repo) RemoteURL() string {
	rem, err := g.r.Remote(remoteName)
	if err != nil || len(rem.Config().URLs) == 0 {
		return ""
	}
	return rem.Config().URLs[0]
}

// branch returns the checked-out branch name ("main").
func (g *Repo) branch() (string, error) {
	head, err := g.r.Reference(plumbing.HEAD, false)
	if err != nil {
		return "", err
	}
	if head.Type() != plumbing.SymbolicReference {
		return "", errors.New("HEAD is detached")
	}
	return head.Target().Short(), nil
}

// Upstream is the branch's remote-tracking ref, e.g. "origin/main", or
// "" when no upstream is configured (`git rev-parse @{u}`).
func (g *Repo) Upstream() string {
	b, err := g.branch()
	if err != nil {
		return ""
	}
	cfg, err := g.r.Config()
	if err != nil {
		return ""
	}
	bc, ok := cfg.Branches[b]
	if !ok || bc.Remote == "" || bc.Merge == "" {
		return ""
	}
	return bc.Remote + "/" + bc.Merge.Short()
}

// upstreamBranch is the remote branch pushed to (the upstream's name,
// else the local branch name).
func (g *Repo) upstreamBranch() (local, remote string, err error) {
	local, err = g.branch()
	if err != nil {
		return "", "", err
	}
	remote = local
	if cfg, err := g.r.Config(); err == nil {
		if bc, ok := cfg.Branches[local]; ok && bc.Merge != "" {
			remote = bc.Merge.Short()
		}
	}
	return local, remote, nil
}

// Fetch updates origin's remote-tracking refs.
func (g *Repo) Fetch() error {
	if url := g.RemoteURL(); url != "" && isLocalURL(url) {
		return g.fetchLocal(url)
	}
	err := withAuth(g.RemoteURL(), func(a transport.AuthMethod) error {
		return g.r.Fetch(&git.FetchOptions{RemoteName: remoteName, Auth: a})
	})
	if errors.Is(err, git.NoErrAlreadyUpToDate) || errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil
	}
	return err
}

// Resolve turns HEAD, origin/main, a branch or a hash into a commit.
func (g *Repo) Resolve(rev string) (*object.Commit, error) {
	h, err := g.r.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		// go-git doesn't resolve "origin/main" by short name in every version.
		if ref, rerr := g.r.Reference(plumbing.NewRemoteReferenceName(splitRemote(rev)), true); rerr == nil {
			h2 := ref.Hash()
			h = &h2
		} else {
			return nil, fmt.Errorf("unknown revision %q: %w", rev, err)
		}
	}
	return g.r.CommitObject(*h)
}

func splitRemote(rev string) (string, string) {
	i := strings.Index(rev, "/")
	if i < 0 {
		return remoteName, rev
	}
	return rev[:i], rev[i+1:]
}

// ancestors returns every commit hash reachable from c (c included).
func ancestors(c *object.Commit) (map[plumbing.Hash]bool, error) {
	seen := map[plumbing.Hash]bool{}
	stack := []*object.Commit{c}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur.Hash] {
			continue
		}
		seen[cur.Hash] = true
		err := cur.Parents().ForEach(func(p *object.Commit) error {
			if !seen[p.Hash] {
				stack = append(stack, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return seen, nil
}

// Count returns how many commits are reachable from to but not from
// from (`git rev-list --count from..to`).
func (g *Repo) Count(from, to string) (int, error) {
	list, err := g.rangeCommits(from, to)
	return len(list), err
}

// rangeCommits lists from..to, newest first.
func (g *Repo) rangeCommits(from, to string) ([]*object.Commit, error) {
	tc, err := g.Resolve(to)
	if err != nil {
		return nil, err
	}
	exclude := map[plumbing.Hash]bool{}
	if from != "" {
		fc, err := g.Resolve(from)
		if err != nil {
			return nil, err
		}
		if exclude, err = ancestors(fc); err != nil {
			return nil, err
		}
	}
	all, err := ancestors(tc)
	if err != nil {
		return nil, err
	}
	var out []*object.Commit
	for h := range all {
		if exclude[h] {
			continue
		}
		c, err := g.r.CommitObject(h)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Committer.When.After(out[j].Committer.When) })
	return out, nil
}

// LogOneline writes up to n commits of from..to as "<short> <subject>".
func (g *Repo) LogOneline(w io.Writer, from, to string, n int) error {
	list, err := g.rangeCommits(from, to)
	if err != nil {
		return err
	}
	for i, c := range list {
		if n > 0 && i >= n {
			break
		}
		subject, _, _ := strings.Cut(c.Message, "\n")
		fmt.Fprintf(w, "%s %s\n", c.Hash.String()[:7], subject)
	}
	return nil
}

// MergeBase returns a best common ancestor of a and b.
func (g *Repo) MergeBase(a, b string) (string, error) {
	ca, err := g.Resolve(a)
	if err != nil {
		return "", err
	}
	cb, err := g.Resolve(b)
	if err != nil {
		return "", err
	}
	bases, err := ca.MergeBase(cb)
	if err != nil {
		return "", err
	}
	if len(bases) == 0 {
		return "", errors.New("no common ancestor")
	}
	return bases[0].Hash.String(), nil
}

// Show returns a file's content at rev (`git show rev:path`).
// Files lists every blob of the commit at rev as path → blob hash
// (`git ls-tree -r rev`).
func (g *Repo) Files(rev string) (map[string]string, error) {
	c, err := g.Resolve(rev)
	if err != nil {
		return nil, err
	}
	it, err := c.Files()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	err = it.ForEach(func(f *object.File) error {
		out[f.Name] = f.Hash.String()
		return nil
	})
	return out, err
}

func (g *Repo) Show(rev, path string) ([]byte, error) {
	c, err := g.Resolve(rev)
	if err != nil {
		return nil, err
	}
	f, err := c.File(path)
	if err != nil {
		return nil, fmt.Errorf("%s at %s: %w", path, rev, err)
	}
	s, err := f.Contents()
	return []byte(s), err
}

func (g *Repo) isAncestor(a, b *object.Commit) (bool, error) {
	if a.Hash == b.Hash {
		return true, nil
	}
	return a.IsAncestor(b)
}

// headCommit returns HEAD's commit, or nil on an unborn branch.
func (g *Repo) headCommit() (*object.Commit, error) {
	ref, err := g.r.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g.r.CommitObject(ref.Hash())
}

// FastForward moves the branch to rev when HEAD is behind it, keeping
// unrelated uncommitted files (`git merge --ff-only rev`).
func (g *Repo) FastForward(rev string) error {
	target, err := g.Resolve(rev)
	if err != nil {
		return err
	}
	head, err := g.headCommit()
	if err != nil {
		return err
	}
	if head != nil {
		if ok, err := g.isAncestor(target, head); err != nil {
			return err
		} else if ok {
			return nil // already contains it
		}
		if ok, err := g.isAncestor(head, target); err != nil {
			return err
		} else if !ok {
			return ErrNotFastForward
		}
	}
	return g.moveBranch(target.Hash, git.MergeReset)
}

// moveBranch points the current branch at h and updates the worktree.
func (g *Repo) moveBranch(h plumbing.Hash, mode git.ResetMode) error {
	w, err := g.r.Worktree()
	if err != nil {
		return err
	}
	b, err := g.branch()
	if err != nil {
		return err
	}
	if err := g.r.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(b), h)); err != nil {
		return err
	}
	return w.Reset(&git.ResetOptions{Commit: h, Mode: mode})
}

// PullFFOnly fetches and fast-forwards (`git pull --ff-only`). Being
// ahead of the remote is fine; having diverged is ErrNotFastForward.
func (g *Repo) PullFFOnly() error {
	if err := g.Fetch(); err != nil {
		return err
	}
	up := g.Upstream()
	if up == "" {
		return errors.New("no upstream configured for the current branch")
	}
	if _, err := g.Resolve(up); err != nil {
		return nil // the remote branch doesn't exist yet: nothing to pull
	}
	return g.FastForward(up)
}

// ResetHard points the branch at rev and discards local changes.
func (g *Repo) ResetHard(rev string) error {
	c, err := g.Resolve(rev)
	if err != nil {
		return err
	}
	return g.moveBranch(c.Hash, git.HardReset)
}

// Add stages paths with their deletions (`git add -A paths…`); no
// paths means the whole tree.
func (g *Repo) Add(paths ...string) error {
	w, err := g.r.Worktree()
	if err != nil {
		return err
	}
	if len(paths) == 0 || (len(paths) == 1 && paths[0] == ".") {
		return w.AddWithOptions(&git.AddOptions{All: true})
	}
	for _, p := range paths {
		if err := w.AddWithOptions(&git.AddOptions{Path: filepath.ToSlash(filepath.Clean(p))}); err != nil {
			// A path that was never tracked and doesn't exist: git add -A
			// ignores it only when it matches nothing; mirror the error.
			return fmt.Errorf("add %s: %w", p, err)
		}
	}
	return nil
}

// Commit records the index. Without allowEmpty a clean tree returns
// ErrNothingToCommit.
func (g *Repo) Commit(msg string, allowEmpty bool) error {
	w, err := g.r.Worktree()
	if err != nil {
		return err
	}
	_, err = w.Commit(msg, &git.CommitOptions{Author: g.signature(), AllowEmptyCommits: allowEmpty})
	if errors.Is(err, git.ErrEmptyCommit) {
		return ErrNothingToCommit
	}
	return err
}

// MergeOurs records a merge of rev that keeps HEAD's tree (`git merge
// -s ours --no-ff -m msg rev`). dop has already written the merged
// vault itself; this only joins the two histories. The index and
// worktree are left as they are.
func (g *Repo) MergeOurs(rev, msg string) error {
	other, err := g.Resolve(rev)
	if err != nil {
		return err
	}
	head, err := g.headCommit()
	if err != nil {
		return err
	}
	if head == nil {
		return errors.New("cannot merge into an empty branch")
	}
	if ok, err := g.isAncestor(other, head); err != nil {
		return err
	} else if ok {
		return nil // already merged
	}
	sig := g.signature()
	c := &object.Commit{
		Author:       *sig,
		Committer:    *sig,
		Message:      msg + "\n",
		TreeHash:     head.TreeHash,
		ParentHashes: []plumbing.Hash{head.Hash, other.Hash},
	}
	obj := g.r.Storer.NewEncodedObject()
	if err := c.Encode(obj); err != nil {
		return err
	}
	h, err := g.r.Storer.SetEncodedObject(obj)
	if err != nil {
		return err
	}
	b, err := g.branch()
	if err != nil {
		return err
	}
	return g.r.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(b), h))
}

// Push sends the current branch to its upstream. force uses a lease on
// the remote-tracking ref (`git push --force-with-lease`).
func (g *Repo) Push(force bool) error {
	local, remote, err := g.upstreamBranch()
	if err != nil {
		return err
	}
	spec := gitconfig.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", local, remote))
	opts := &git.PushOptions{RemoteName: remoteName, RefSpecs: []gitconfig.RefSpec{spec}}
	if force {
		opts.RefSpecs = []gitconfig.RefSpec{"+" + spec}
		opts.ForceWithLease = &git.ForceWithLease{RefName: plumbing.NewBranchReferenceName(remote)}
		if ref, err := g.r.Reference(plumbing.NewRemoteReferenceName(remoteName, remote), true); err == nil {
			opts.ForceWithLease.Hash = ref.Hash()
		}
	}
	err = withAuth(g.RemoteURL(), func(a transport.AuthMethod) error {
		opts.Auth = a
		return g.r.Push(opts)
	})
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		err = nil
	}
	if err == nil {
		// Like git, record what the remote now has.
		if head, herr := g.r.Head(); herr == nil {
			_ = g.r.Storer.SetReference(plumbing.NewHashReference(plumbing.NewRemoteReferenceName(remoteName, remote), head.Hash()))
		}
	}
	return err
}

// signature is the commit author: git's configured user (repo, then
// global, then system), else a dop identity — a fresh VPS has no git
// config and git itself would refuse to commit there.
func (g *Repo) signature() *object.Signature {
	sig := &object.Signature{Name: "dop", Email: "dop@localhost", When: time.Now()}
	for _, scope := range []gitconfig.Scope{gitconfig.LocalScope, gitconfig.GlobalScope, gitconfig.SystemScope} {
		cfg, err := g.r.ConfigScoped(scope)
		if err != nil {
			continue
		}
		if cfg.User.Name != "" && cfg.User.Email != "" {
			sig.Name, sig.Email = cfg.User.Name, cfg.User.Email
			break
		}
		if cfg.Author.Name != "" && cfg.Author.Email != "" {
			sig.Name, sig.Email = cfg.Author.Name, cfg.Author.Email
			break
		}
	}
	return sig
}

// isLocalURL: a path or file:// URL (served in-process, no auth).
func isLocalURL(url string) bool {
	ep, err := transport.NewEndpoint(url)
	return err == nil && ep.Protocol == "file"
}
