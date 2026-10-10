#!/usr/bin/env python3
"""DOP key-leak matrix (e2e v1_1820): does an injected key reach what a harness\ncaptures?: does an injected key reach what a harness captures?
Each case runs a dop command with stdout/stderr wired like a given harness
(pipe = Claude Code Bash tool; pty = Cursor / VS Code / node-pty terminals) and
looks for the fake key value in everything captured."""
import os, pty, subprocess, sys, select, json, fcntl, termios

DOP = sys.argv[1]
SECRET = sys.argv[3]
BEARER = sys.argv[2]
HOME_DIR = sys.argv[4]
BASE = dict(os.environ, DOP_HOME=HOME_DIR, DOP_NO_TUI="1", DOP_NO_NOTIFY="1",
            DOP_NO_KEYCHAIN="1", DOP_ALLOW_FILE_KEYS="1")
BASE.pop("DOP_APPROVAL_PASSPHRASE", None)

def run(argv, out_mode, err_mode, env):
    """out_mode/err_mode: 'pipe' | 'pty'. stdin follows stdout's mode."""
    master = slave = None
    if "pty" in (out_mode, err_mode):
        master, slave = pty.openpty()
    stdout = slave if out_mode == "pty" else subprocess.PIPE
    stderr = slave if err_mode == "pty" else subprocess.PIPE
    stdin = slave if out_mode == "pty" else subprocess.DEVNULL
    def ctty():
        # Like node-pty: new session, the pty becomes the controlling
        # terminal (so /dev/tty writes land in what the harness reads).
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    pre = ctty if out_mode == "pty" else None
    p = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr, env=env, close_fds=True, preexec_fn=pre)
    if slave is not None:
        os.close(slave)
    captured = b""
    if master is not None:
        while True:
            r, _, _ = select.select([master], [], [], 5)
            if not r:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            captured += chunk
            # Answer Bubble Tea's startup colour / cursor query the way a
            # real terminal (xterm.js in Cursor / VS Code) does, at once.
            if b"\x1b]11;?" in chunk:
                os.write(master, b"\x1b]11;rgb:1e1e/1e1e/1e1e\x1b\\\x1b[1;1R")
    o, e = p.communicate(timeout=20)
    captured += (o or b"") + (e or b"")
    if master is not None:
        os.close(master)
    return p.returncode, captured.decode(errors="replace")

cases = []
def case(name, argv, out_mode, err_mode, bearer=True, extra=None):
    env = dict(BASE)
    if bearer:
        env["DOP_TOKEN"] = BEARER
    if extra:
        env.update(extra)
    rc, cap = run(argv, out_mode, err_mode, env)
    leak = SECRET in cap
    masked = "‹NOTION_TOKEN›" in cap
    cases.append((name, out_mode, err_mode, rc, "LEAK" if leak else ("masked" if masked else "no value")))

X = [DOP, "exec", "--"]
case("exec printenv (stdout)",          X + ["printenv", "NOTION_TOKEN"], "pipe", "pipe")
case("exec printenv (stdout)",          X + ["printenv", "NOTION_TOKEN"], "pty",  "pty")
case("exec printenv (stdout)",          X + ["printenv", "NOTION_TOKEN"], "pty",  "pipe")
case("exec printenv (stdout)",          X + ["printenv", "NOTION_TOKEN"], "pipe", "pty")
case("exec echo to stderr",             X + ["sh", "-c", 'echo "$NOTION_TOKEN" >&2'], "pipe", "pipe")
case("exec echo to stderr",             X + ["sh", "-c", 'echo "$NOTION_TOKEN" >&2'], "pty",  "pty")
case("exec env dump",                   X + ["env"], "pty", "pty")
case("exec bearer-free printenv",       X + ["printenv", "NOTION_TOKEN"], "pty", "pty", bearer=False)
case("exec bearer-free printenv",       X + ["printenv", "NOTION_TOKEN"], "pipe", "pipe", bearer=False)
case("exec write to /dev/tty",         X + ["sh", "-c", 'echo "$NOTION_TOKEN" > /dev/tty'], "pty", "pty")
case("exec via script(1)",              ["script", "-q", "/dev/null"] + X + ["printenv", "NOTION_TOKEN"], "pipe", "pipe")
case("exec via expect",                 ["expect", "-c", "spawn " + " ".join(X + ["printenv", "NOTION_TOKEN"]) + "; expect eof"], "pipe", "pipe")
import shutil
if shutil.which("sandbox-exec"):  # macOS: a terminal where pty creation is forbidden (Cursor-style sandbox)
    NOPTY = '(version 1)(allow default)(deny file-read* file-write* (literal "/dev/ptmx"))'
    case("exec in sandbox without pty",  ["sandbox-exec", "-p", NOPTY] + X + ["printenv", "NOTION_TOKEN"], "pty", "pty")
case("exec --inherit-env printenv",     [DOP, "exec", "--inherit-env", "--", "printenv", "NOTION_TOKEN"], "pty", "pty")
# dop env: wrong scripted passphrase so a gate refuses without a desktop popup
W = {"DOP_APPROVAL_PASSPHRASE": "wrong-on-purpose"}
case("env (bound, gate)",               [DOP, "env"], "pipe", "pipe", extra=W)
case("env (bound, gate)",               [DOP, "env"], "pty",  "pty",  extra=W)
case("env (bound, no passphrase)",      [DOP, "env"], "pipe", "pipe")
case("env (bound, no passphrase)",      [DOP, "env"], "pty",  "pty")  # refused before any approval popup

print(f"{'case':34} {'stdout':6} {'stderr':6} {'rc':>3}  result")
for n, o, e, rc, res in cases:
    print(f"{n:34} {o:6} {e:6} {rc:>3}  {res}")
leaks = sum(1 for c in cases if c[4] == "LEAK")
print(f"\n{leaks} leak(s) in {len(cases)} cases")
sys.exit(1 if leaks else 0)
