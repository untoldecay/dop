# Demo clips

Reproducible terminal recordings of dop for posts and docs. Nothing here
writes into the repo: the throwaway install lives under `/tmp/dopdemo`,
the clips land on your Desktop.

```
scripts/demo/record.sh            # stage + record exec, proof, tui
scripts/demo/record.sh tui        # one clip
OUT=~/clips scripts/demo/record.sh
```

Needs `vhs`, `ffmpeg`, `go`. About a minute for the three clips.

## What gets recorded

| Tape | Clip | Scenario |
|---|---|---|
| `exec` | `dop-exec-light.mp4` | the agent runs with the Notion key, the transcript sees `‹NOTION_TOKEN›`; two comment beats; the repo link |
| `proof` | `dop-exec-proof-light.mp4` | `len: 44` inside the process, then `dop token revoke` |
| `tui` | `dop-tui-light.mp4` | `dop`, Login, List › Integrations, open notion, Credentials tab |

Every clip: 1280×960, white theme (`theme-light.json`), font 28, a
placeholder prompt `camille@mini ~ %`. The TUI runs with `DOP_THEME=light`.

## How it works

`stage.sh` builds dop from this checkout, creates a fresh vault under a
throwaway `HOME` with three fake integrations (Notion, YouTube, Linear),
issues and claims a P-256 agent named `buzz-reader`, reseals it so
bearer-free exec works, and leaves the admin logged in. The path is short
on purpose: the daemon's unix socket cannot live under a long path.

`record.sh` copies the tapes to the demo root, fills in the root path and
the theme, runs VHS per tape in the right session state (logged in for
`proof`, logged out for `tui`), extracts the last frame of each clip for
a quick check, and copies mp4 + gif to `OUT`.

Passphrases and keys in `stage.sh` are fake and demo-only.

## Editing

- Timings and copy live in `tapes/*.tape`; the shared header (size, font,
  theme, env, prompt) is `tapes/common.tape`.
- Long commands are typed with a `\` continuation so the type can stay big.
- After changing a tape, check `/tmp/dopdemo/work/frames/*-end.png`.
- To clean up: `scripts/demo/stage.sh --clean` (logs the demo daemon out, removes `/tmp/dopdemo`).
