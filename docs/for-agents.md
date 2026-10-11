# For AI agents: installing DOP for your user

You're an AI agent and your user pointed you at this repo, maybe with "install
this". This page is for you. Follow it in order, and **ask before each step that
changes their machine**.

DOP keeps your user's API keys in an encrypted vault (a private git repo they
own) and gives you a *pass* (a **bearer**) for exactly the tools you need. You
never see the keys: `dop exec` hands them to the one command you run.

## The rule that matters most

**The admin side is the human's job, on their own computer.** Never create a DOP
admin on the machine you run on, never ask for the admin or approval
passphrase, never ask for the vault's keys. The point of DOP is that the machine
running agents can't change what agents get. If you hold the admin, that's gone.

You may *explain* the admin steps. The human types them.

## 1. Ask first

Before installing anything, ask:

1. "Do you want me to install DOP here, so I can use your tools without you
   pasting keys into this chat?"
2. "Do you already have a DOP vault (a private git repo you set up with DOP on
   your computer)?" If yes, ask for its URL and go to [step 3](#3-install-dop-here-server-side).
   If no, go to step 2.

## 2. The user creates their vault (on their own computer)

Give the user these steps. They do them, not you:

1. **Create an empty private repo** on GitHub or GitLab (e.g. `dop-vault`). No
   README, no files.
2. **Install DOP on their computer:**
   ```
   curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
   ```
3. **Run `dop`**, pick **New setup**, choose an admin passphrase and an approval
   passphrase (keep both somewhere safe), then **Attach vault** with the repo's
   URL (`https://github.com/<them>/dop-vault`).
4. **Add their first tool** in the app (Add › Integration, e.g. a Notion or
   GitHub token).
5. **Send you the vault URL.** Only the URL; nothing else from that machine.

## 3. Install DOP here (server side)

On the machine you run on, after the user says yes:

```bash
curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
dop init --cache <VAULT-URL>
dop doctor
```

- No other prerequisite: DOP encrypts and syncs the vault itself (git and sops
  aren't needed).
- If `dop` isn't found after install, it's in `~/.local/bin`: add it to `PATH`
  (the installer prints the line).
- `dop init --cache` attaches this machine as a **server**: it runs agents, holds
  no admin key. It's the command-line version of the app's **Server** screen.
- `dop doctor` should show `binary:git` and `binary:sops` as "not needed".

### If the vault repo refuses the login

`dop init --cache` may fail with **"github.com refused every login dop tried"**.
That's expected on a fresh server: it has no git login for the private repo.

Ask the user to make a **repo token** and save it here **themselves**:

1. GitHub › Settings › Developer settings › **Fine-grained tokens** › Generate:
   only the vault repo, **Contents: Read and write**. (GitLab: a project access
   token with `read_repository` + `write_repository`.)
2. On this machine, the user runs `dop vault login github.com` in their own
   terminal (an SSH session to the server, not through you) and pastes the token
   at the hidden prompt. Or they open `dop` there, pick **Server**, and paste it
   when asked.
3. Then retry `dop init --cache <VAULT-URL>`.

**Don't ask the user to paste the token into the chat.** Chat transcripts are
stored; a token there is a leaked token.

SSH URLs (`git@github.com:…`) work too when this machine has an SSH key the
user added to their account.

## 4. Wait for the handoff

Tell the user: *"DOP is installed. On your computer, open `dop`, Issue a bearer
for me with the tools I need, and paste me the text it gives you."*

They paste something like:

```
Scoped credential access via DOP — run:

  DOP_TOKEN=tok_… DOP_ALLOW_FILE_KEYS=1 dop claim --remote --key-type p256 AB-CD-EF
```

Run that command as is. It creates your own key on this machine and sends the
claim to the vault. Then tell the user: *"Please approve me: on your computer,
Bearers › Pending (or the banner), with your approval passphrase."*

## 5. Use it

Once approved:

```bash
dop exec --agent-name <your-name> -- <command>
```

No `DOP_TOKEN` needed any more: your key on this machine is the proof. If it
says the claim isn't approved yet right after the user approved, run `dop pull`
and retry. The
tool's key reaches only `<command>`, as an environment variable (e.g.
`$NOTION_TOKEN`). Reference it by name inside the command, never by value:

```bash
dop exec --agent-name research -- sh -c 'curl -H "Authorization: Bearer $NOTION_TOKEN" https://api.notion.com/v1/users/me'
```

From here, the DOP skill has the day-to-day rules. Install it with
`dop skill install` (Claude Code), or read it with `dop skill show`.

## When something fails

| You see | What it means | What to do |
|---|---|---|
| `refused every login dop tried` | No login for the vault repo on this machine | [Repo token](#if-the-vault-repo-refuses-the-login), saved by the user |
| `unknown bearer (bundle not found…)` | The vault here doesn't have that bearer yet | Ask the user to `dop push` (or check you're on the right install, below) |
| `PIN expired` / `PIN does not match` | PINs last 1 hour | Ask for a **Re-issue** and a fresh handoff |
| `no active admin session` on `dop claim` | You ran a plain `dop claim` on a server | Use the handoff as given: it has `--remote` |
| Works in one terminal, not in yours | Different DOP install (e.g. `DOP_HOME` set in one only) | `dop doctor` shows `install:home` when `DOP_HOME` is set; your environment must match where the server was set up. Use full paths (`/root/dop-test`), not `~/…`, in config files |

Never work around a failure by asking for the raw key, the admin passphrase or
the vault's age key. If DOP refuses, tell the user what the message says.
