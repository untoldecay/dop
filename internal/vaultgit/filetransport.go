package vaultgit

import (
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/revlist"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// go-git's default file:// transport starts git-upload-pack /
// git-receive-pack — the git binary in disguise. Local vault repos
// (a path, or file://) are served in-process instead.
func init() {
	client.InstallProtocol("file", server.NewClient(localLoader{}))
}

// localLoader opens a bare repo at the path, or the .git of a checkout
// (go-git's DefaultLoader uses the checkout root itself for the latter).
type localLoader struct{}

func (localLoader) Load(ep *transport.Endpoint) (storer.Storer, error) {
	fs := osfs.New(ep.Path)
	if _, err := fs.Stat("config"); err == nil {
		if _, err := fs.Stat("objects"); err == nil {
			return filesystem.NewStorage(fs, cache.NewObjectLRUDefault()), nil
		}
	}
	if fi, err := fs.Stat(".git"); err == nil && fi.IsDir() {
		dot, err := fs.Chroot(".git")
		if err != nil {
			return nil, err
		}
		return filesystem.NewStorage(dot, cache.NewObjectLRUDefault()), nil
	}
	return nil, transport.ErrRepositoryNotFound
}

// fetchLocal fetches from a local remote by copying the objects it
// lacks and updating origin/* — go-git's in-process upload-pack fails
// ("object not found") when the client offers commits the server
// doesn't have, i.e. exactly when the two sides have diverged.
func (g *Repo) fetchLocal(url string) error {
	ep, err := transport.NewEndpoint(url)
	if err != nil {
		return err
	}
	remote, err := localLoader{}.Load(ep)
	if err != nil {
		return err
	}
	refs, err := remote.IterReferences()
	if err != nil {
		return err
	}
	type tip struct {
		name plumbing.ReferenceName
		hash plumbing.Hash
	}
	var tips []tip
	err = refs.ForEach(func(r *plumbing.Reference) error {
		if r.Type() == plumbing.HashReference && r.Name().IsBranch() {
			tips = append(tips, tip{r.Name(), r.Hash()})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, t := range tips {
		if g.r.Storer.HasEncodedObject(t.hash) != nil {
			hashes, err := revlist.Objects(remote, []plumbing.Hash{t.hash}, nil)
			if err != nil {
				return err
			}
			for _, h := range hashes {
				if g.r.Storer.HasEncodedObject(h) == nil {
					continue
				}
				obj, err := remote.EncodedObject(plumbing.AnyObject, h)
				if err != nil {
					return err
				}
				if _, err := g.r.Storer.SetEncodedObject(obj); err != nil {
					return err
				}
			}
		}
		ref := plumbing.NewHashReference(plumbing.NewRemoteReferenceName(remoteName, t.name.Short()), t.hash)
		if err := g.r.Storer.SetReference(ref); err != nil {
			return err
		}
	}
	return nil
}
