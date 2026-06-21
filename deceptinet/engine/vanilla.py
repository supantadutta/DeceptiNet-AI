"""Vanilla (baseline) response engine — templated/canned responses, no LLM.

This is the *baseline* honeypot for the thesis A/B comparison, so it must be a
fair, genuinely-solid baseline (spec §1, Phase 1): the comparison rests on it.
It deliberately does NOT try to be clever about novel commands — handling the
long tail of unknown commands is precisely what the LLM mode is meant to add,
and a baseline that faked that would invalidate the experiment.

Hard rule: NOTHING here executes real commands or touches the host. Every
response is synthesised from the in-memory :class:`SessionState`.
"""

from __future__ import annotations

import shlex
import time

from deceptinet.engine.base import EngineResult, ResponseEngine
from deceptinet.session.state import SessionState
from deceptinet.session.vfs import VfsError

# Commands an attacker might run that we knowingly do NOT emulate fully. We
# return a plausible response but record the gap honestly (meta) rather than
# pretending. Pipe/redirection semantics are bounded — see LIMITATIONS.md.

_FIXED_DATE = "Oct 30 12:00"


class VanillaEngine(ResponseEngine):
    mode = "vanilla"

    def __init__(self) -> None:
        self._handlers = {
            "echo": self._cmd_echo,
            "pwd": self._cmd_pwd,
            "whoami": self._cmd_whoami,
            "id": self._cmd_id,
            "hostname": self._cmd_hostname,
            "uname": self._cmd_uname,
            "ls": self._cmd_ls,
            "dir": self._cmd_ls,
            "cd": self._cmd_cd,
            "cat": self._cmd_cat,
            "mkdir": self._cmd_mkdir,
            "rmdir": self._cmd_rmdir,
            "rm": self._cmd_rm,
            "touch": self._cmd_touch,
            "env": self._cmd_env,
            "printenv": self._cmd_env,
            "export": self._cmd_export,
            "set": self._cmd_env,
            "which": self._cmd_which,
            "history": self._cmd_history,
            "clear": self._cmd_clear,
            "ps": self._cmd_ps,
            "uptime": self._cmd_uptime,
            "w": self._cmd_w,
            "who": self._cmd_who,
            "free": self._cmd_free,
            "df": self._cmd_df,
            "wget": self._cmd_fetch,
            "curl": self._cmd_fetch,
        }

    async def respond(self, command_line: str, state: SessionState) -> EngineResult:
        start = time.perf_counter()
        result = self._respond_sync(command_line, state)
        result.latency_ms = (time.perf_counter() - start) * 1000.0
        result.engine_mode = self.mode
        return result

    # ------------------------------------------------------------------
    def _respond_sync(self, command_line: str, state: SessionState) -> EngineResult:
        line = command_line.strip()
        if line:
            state.history.append(line)
        if not line:
            return EngineResult(output="")

        # Session-ending commands.
        first = line.split()[0]
        if first in ("exit", "logout", "quit"):
            return EngineResult(output="logout\n", close_session=True)

        segments = _split_sequence(line)
        outputs: list[str] = []
        last_status = 0
        meta: dict = {}
        for sep, segment in segments:
            if sep == "&&" and last_status != 0:
                continue  # short-circuit like a real shell
            text, last_status, seg_meta = self._run_segment(segment, state)
            outputs.append(text)
            if seg_meta:
                meta.update(seg_meta)

        return EngineResult(
            output="".join(outputs), exit_status=last_status, meta=meta
        )

    def _run_segment(self, segment: str, state: SessionState) -> tuple[str, int, dict]:
        segment = segment.strip()
        if not segment:
            return "", 0, {}

        meta: dict = {}

        # Bounded pipe handling: run the left-most stage, record that we did not
        # interpret the pipeline (honest — see LIMITATIONS.md).
        if _has_top_level(segment, "|"):
            segment = _split_once(segment, "|")[0].strip()
            meta["pipe_unhandled"] = True

        # Single trailing redirect: capture output into the VFS instead of stdout.
        redirect = None
        for op in (">>", ">"):
            if _has_top_level(segment, op):
                cmd_part, target = _split_once(segment, op)
                redirect = (op, target.strip())
                segment = cmd_part.strip()
                break

        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            return "", 0, meta

        # Strip a leading `sudo` (and its simple options) — bots use it freely.
        while tokens and tokens[0] == "sudo":
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                tokens = tokens[1:]
            if tokens and tokens[0] == "-u" and len(tokens) > 1:
                tokens = tokens[2:]
        if not tokens:
            return "", 0, meta

        tokens = [_expand_env(tok, state) for tok in tokens]
        cmd, args = tokens[0], tokens[1:]

        handler = self._handlers.get(cmd)
        if handler is None:
            meta["unknown_command"] = cmd
            return f"{_basename(cmd)}: command not found\n", 127, meta

        text, status = handler(args, state)

        if redirect is not None:
            op, target = redirect
            abspath = state.fs.normalize(target, state.cwd)
            try:
                if op == ">>" and state.fs.exists(abspath):
                    existing = state.fs.read(abspath)
                    state.fs.write_file(abspath, existing + text, owner=state.username)
                else:
                    state.fs.write_file(abspath, text, owner=state.username)
                return "", status, meta
            except VfsError as exc:
                return f"bash: {target}: {exc.errno_text}\n", 1, meta

        return text, status, meta

    # ---- command handlers --------------------------------------------
    # Each returns (output_text, exit_status). Output includes trailing newline
    # when a real command would produce one.

    def _cmd_echo(self, args: list[str], state: SessionState) -> tuple[str, int]:
        newline = True
        if args and args[0] == "-n":
            newline = False
            args = args[1:]
        text = " ".join(args)
        return (text + "\n") if newline else text, 0

    def _cmd_pwd(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return state.cwd + "\n", 0

    def _cmd_whoami(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return state.username + "\n", 0

    def _cmd_id(self, args: list[str], state: SessionState) -> tuple[str, int]:
        u = next((x for x in state.persona.users if x.name == state.username), None)
        if u is None:
            uid = gid = 0 if state.is_root else 1000
            name = state.username
            return f"uid={uid}({name}) gid={gid}({name}) groups={gid}({name})\n", 0
        groups = f"{u.gid}({u.name})"
        if u.name == "root":
            groups = "0(root)"
        return f"uid={u.uid}({u.name}) gid={u.gid}({u.name}) groups={groups}\n", 0

    def _cmd_hostname(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return state.hostname + "\n", 0

    def _cmd_uname(self, args: list[str], state: SessionState) -> tuple[str, int]:
        p = state.persona
        if not args or args == ["-s"]:
            return "Linux\n", 0
        if "-a" in args:
            return p.uname_a + "\n", 0
        parts: list[str] = []
        for flag in args:
            if flag in ("-r", "--kernel-release"):
                parts.append(p.kernel)
            elif flag in ("-s", "--kernel-name"):
                parts.append("Linux")
            elif flag in ("-n", "--nodename"):
                parts.append(p.hostname)
            elif flag in ("-m", "--machine"):
                parts.append(p.arch)
            elif flag in ("-o", "--operating-system"):
                parts.append("GNU/Linux")
            elif flag in ("-p", "-i"):
                parts.append(p.arch)
        if not parts:
            return "Linux\n", 0
        return " ".join(parts) + "\n", 0

    def _cmd_ls(self, args: list[str], state: SessionState) -> tuple[str, int]:
        show_all = False
        long_fmt = False
        paths: list[str] = []
        for a in args:
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                if "a" in a:
                    show_all = True
                if "l" in a:
                    long_fmt = True
            elif a in ("--all",):
                show_all = True
            elif a.startswith("-"):
                continue
            else:
                paths.append(a)

        targets = paths or ["."]
        out_blocks: list[str] = []
        status = 0
        for target in targets:
            abspath = state.fs.normalize(target, state.cwd)
            if not state.fs.exists(abspath):
                out_blocks.append(
                    f"ls: cannot access '{target}': No such file or directory\n"
                )
                status = 2
                continue
            if not state.fs.is_dir(abspath):
                # Listing a single file just prints its name.
                out_blocks.append(target + "\n")
                continue
            names = state.fs.listdir(abspath)
            if show_all:
                names = [".", ".."] + names
            if long_fmt:
                out_blocks.append(self._ls_long(abspath, names, show_all, state))
            else:
                out_blocks.append(("  ".join(names) + "\n") if names else "")
        return "".join(out_blocks), status

    def _ls_long(
        self, abspath: str, names: list[str], show_all: bool, state: SessionState
    ) -> str:
        lines = []
        total = 0
        for name in names:
            if name in (".", ".."):
                mode = "drwxr-xr-x"
                owner = "root"
                size = 4096
                is_dir = True
            else:
                child = state.fs.normalize(name, abspath)
                info = state.fs.stat(child)
                is_dir = info.is_dir
                mode = ("d" if is_dir else "-") + info.mode
                owner = info.owner
                size = info.size
            total += 4 if is_dir else max(1, (size // 1024) + 1)
            lines.append(
                f"{mode} 1 {owner} {owner} {size:>6} {_FIXED_DATE} {name}"
            )
        return f"total {total}\n" + "\n".join(lines) + ("\n" if lines else "")

    def _cmd_cd(self, args: list[str], state: SessionState) -> tuple[str, int]:
        target = args[0] if args else state.home
        if target == "-":
            target = state.env.get("OLDPWD", state.cwd)
        if target.startswith("~"):
            target = state.home + target[1:]
        abspath = state.fs.normalize(target, state.cwd)
        if not state.fs.exists(abspath):
            return f"bash: cd: {target}: No such file or directory\n", 1
        if not state.fs.is_dir(abspath):
            return f"bash: cd: {target}: Not a directory\n", 1
        state.env["OLDPWD"] = state.cwd
        state.cwd = abspath
        state.env["PWD"] = abspath
        return "", 0

    def _cmd_cat(self, args: list[str], state: SessionState) -> tuple[str, int]:
        if not args:
            # Real cat with no args reads stdin; in a bot context this would hang.
            # We return nothing rather than block.
            return "", 0
        out: list[str] = []
        status = 0
        for target in args:
            if target.startswith("-"):
                continue
            abspath = state.fs.normalize(target, state.cwd)
            try:
                content = state.fs.read(abspath)
                out.append(content if content.endswith("\n") or content == "" else content + "\n")
            except VfsError as exc:
                out.append(f"cat: {target}: {exc.errno_text}\n")
                status = 1
        return "".join(out), status

    def _cmd_mkdir(self, args: list[str], state: SessionState) -> tuple[str, int]:
        parents = False
        targets = []
        for a in args:
            if a in ("-p", "--parents"):
                parents = True
            elif a.startswith("-"):
                continue
            else:
                targets.append(a)
        if not targets:
            return "mkdir: missing operand\n", 1
        status = 0
        msgs: list[str] = []
        for target in targets:
            abspath = state.fs.normalize(target, state.cwd)
            try:
                if parents:
                    state.fs.makedirs(abspath, owner=state.username)
                else:
                    state.fs.mkdir(abspath, owner=state.username)
            except VfsError as exc:
                msgs.append(f"mkdir: cannot create directory '{target}': {exc.errno_text}\n")
                status = 1
        return "".join(msgs), status

    def _cmd_rmdir(self, args: list[str], state: SessionState) -> tuple[str, int]:
        status = 0
        msgs: list[str] = []
        for target in [a for a in args if not a.startswith("-")]:
            abspath = state.fs.normalize(target, state.cwd)
            try:
                if not state.fs.is_dir(abspath):
                    raise VfsError("Not a directory")
                if state.fs.listdir(abspath):
                    raise VfsError("Directory not empty")
                state.fs.remove(abspath)
            except VfsError as exc:
                msgs.append(f"rmdir: failed to remove '{target}': {exc.errno_text}\n")
                status = 1
        return "".join(msgs), status

    def _cmd_rm(self, args: list[str], state: SessionState) -> tuple[str, int]:
        # SIMULATED removal — only the in-memory VFS is touched. The host is
        # never affected. See tests/test_no_real_execution.py.
        force = False
        targets = []
        for a in args:
            if a.startswith("-"):
                if "f" in a:
                    force = True
                continue
            targets.append(a)
        status = 0
        msgs: list[str] = []
        for target in targets:
            abspath = state.fs.normalize(target, state.cwd)
            try:
                state.fs.remove(abspath)
            except VfsError as exc:
                if not force:
                    msgs.append(f"rm: cannot remove '{target}': {exc.errno_text}\n")
                    status = 1
        return "".join(msgs), status

    def _cmd_touch(self, args: list[str], state: SessionState) -> tuple[str, int]:
        status = 0
        for target in [a for a in args if not a.startswith("-")]:
            abspath = state.fs.normalize(target, state.cwd)
            if not state.fs.exists(abspath):
                try:
                    state.fs.write_file(abspath, "", owner=state.username)
                except VfsError as exc:
                    return f"touch: cannot touch '{target}': {exc.errno_text}\n", 1
        return "", status

    def _cmd_env(self, args: list[str], state: SessionState) -> tuple[str, int]:
        lines = [f"{k}={v}" for k, v in state.env.items()]
        return "\n".join(lines) + "\n", 0

    def _cmd_export(self, args: list[str], state: SessionState) -> tuple[str, int]:
        for a in args:
            if "=" in a:
                k, _, v = a.partition("=")
                state.env[k] = v
        return "", 0

    def _cmd_which(self, args: list[str], state: SessionState) -> tuple[str, int]:
        out = []
        status = 0
        for a in args:
            if a in self._handlers or a in ("bash", "sh", "python3", "python"):
                out.append(f"/usr/bin/{a}\n")
            else:
                status = 1
        return "".join(out), status

    def _cmd_history(self, args: list[str], state: SessionState) -> tuple[str, int]:
        lines = [f"{i + 1:>5}  {cmd}" for i, cmd in enumerate(state.history)]
        return ("\n".join(lines) + "\n") if lines else "", 0

    def _cmd_clear(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return "\x1b[H\x1b[2J\x1b[3J", 0

    def _cmd_ps(self, args: list[str], state: SessionState) -> tuple[str, int]:
        out = (
            "    PID TTY          TIME CMD\n"
            "      1 ?        00:00:01 systemd\n"
            "    412 ?        00:00:00 sshd\n"
            "    640 ?        00:00:02 nginx\n"
            "    641 ?        00:00:00 php-fpm\n"
            f"   1893 pts/0    00:00:00 bash\n"
            f"   1920 pts/0    00:00:00 ps\n"
        )
        return out, 0

    def _cmd_uptime(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return (
            " 12:00:01 up 7 days,  3:14,  1 user,  load average: 0.08, 0.03, 0.01\n"
        ), 0

    def _cmd_w(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return (
            " 12:00:01 up 7 days,  3:14,  1 user,  load average: 0.08, 0.03, 0.01\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{state.username:<8} pts/0    10.0.0.5         11:59    0.00s  0.01s  0.00s w\n"
        ), 0

    def _cmd_who(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return f"{state.username:<8} pts/0        2023-10-30 11:59 (10.0.0.5)\n", 0

    def _cmd_free(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:         4012345     1203456     1500000       12345     1308889     2600000\n"
            "Swap:        2097148           0     2097148\n"
        ), 0

    def _cmd_df(self, args: list[str], state: SessionState) -> tuple[str, int]:
        return (
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            "/dev/vda1       41251136 8123456  31012345  21% /\n"
            "tmpfs            2006172       0   2006172   0% /dev/shm\n"
        ), 0

    def _cmd_fetch(self, args: list[str], state: SessionState) -> tuple[str, int]:
        # wget/curl: a key attacker action (malware staging). We NEVER fetch.
        # We record the URL (telemetry captures the full command line) and return
        # a believable but inert response. No outbound connection is made.
        url = next((a for a in args if a.startswith(("http://", "https://", "ftp://"))), None)
        if url is None:
            url = next((a for a in args if not a.startswith("-")), "")
        # Minimal, plausible, and explicitly inert.
        return (
            f"--2023-10-30 12:00:00--  {url}\n"
            "Resolving host... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address\n"
        ), 4


# ---- line-parsing helpers --------------------------------------------------

def _basename(cmd: str) -> str:
    return cmd.rsplit("/", 1)[-1]


def _expand_env(token: str, state: SessionState) -> str:
    if "$" not in token:
        return token
    result = []
    i = 0
    while i < len(token):
        ch = token[i]
        if ch == "$" and i + 1 < len(token):
            nxt = token[i + 1]
            if nxt == "{":
                end = token.find("}", i + 2)
                if end != -1:
                    name = token[i + 2:end]
                    result.append(state.env.get(name, ""))
                    i = end + 1
                    continue
            if nxt.isalpha() or nxt == "_":
                j = i + 1
                while j < len(token) and (token[j].isalnum() or token[j] == "_"):
                    j += 1
                name = token[i + 1:j]
                result.append(state.env.get(name, ""))
                i = j
                continue
        result.append(ch)
        i += 1
    return "".join(result)


def _iter_top_level_quotes(s: str):
    """Yield (index, char, in_quote) skipping quoted regions for operator scans."""
    quote = None
    for idx, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
            yield idx, ch, True
        elif ch in ("'", '"'):
            quote = ch
            yield idx, ch, True
        else:
            yield idx, ch, False


def _has_top_level(s: str, op: str) -> bool:
    return _find_top_level(s, op) != -1


def _find_top_level(s: str, op: str) -> int:
    n = len(op)
    chars = list(_iter_top_level_quotes(s))
    i = 0
    while i < len(chars):
        idx, _, in_quote = chars[i]
        if not in_quote and s[idx:idx + n] == op:
            # Ensure the whole operator is unquoted.
            if all(not chars[idx + k][2] for k in range(n) if idx + k < len(chars)):
                return idx
        i += 1
    return -1


def _split_once(s: str, op: str) -> tuple[str, str]:
    pos = _find_top_level(s, op)
    if pos == -1:
        return s, ""
    return s[:pos], s[pos + len(op):]


def _split_sequence(line: str) -> list[tuple[str, str]]:
    """Split on top-level ``;`` and ``&&`` into (separator, command) pairs.

    The separator is the operator that PRECEDED the command ("" for the first).
    """
    segments: list[tuple[str, str]] = []
    buf = []
    sep = ""
    i = 0
    chars = list(_iter_top_level_quotes(line))
    while i < len(line):
        in_quote = chars[i][2] if i < len(chars) else False
        if not in_quote and line[i:i + 2] == "&&":
            segments.append((sep, "".join(buf)))
            buf = []
            sep = "&&"
            i += 2
            continue
        if not in_quote and line[i] == ";":
            segments.append((sep, "".join(buf)))
            buf = []
            sep = ";"
            i += 1
            continue
        buf.append(line[i])
        i += 1
    segments.append((sep, "".join(buf)))
    return segments
