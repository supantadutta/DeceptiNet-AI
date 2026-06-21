"""Per-session shell state and a factory that seeds a believable filesystem."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from deceptinet.session.personas import Persona, get_persona
from deceptinet.session.vfs import VirtualFS


@dataclass
class SessionState:
    persona: Persona
    username: str
    cwd: str
    env: dict[str, str]
    fs: VirtualFS
    history: list[str] = field(default_factory=list)
    created_at: _dt.datetime = field(
        default_factory=lambda: _dt.datetime.now(tz=_dt.timezone.utc)
    )

    @property
    def hostname(self) -> str:
        return self.persona.hostname

    @property
    def is_root(self) -> bool:
        return self.username == "root"

    @property
    def home(self) -> str:
        return "/root" if self.is_root else f"/home/{self.username}"

    def display_cwd(self) -> str:
        """Render cwd with ``~`` substitution like a real shell."""
        if self.cwd == self.home:
            return "~"
        if self.cwd.startswith(self.home + "/"):
            return "~" + self.cwd[len(self.home):]
        return self.cwd

    def prompt(self) -> str:
        sigil = "#" if self.is_root else "$"
        return f"{self.username}@{self.hostname}:{self.display_cwd()}{sigil} "


def _seed_fs(persona: Persona) -> VirtualFS:
    """Create a plausible Ubuntu-ish filesystem for ``persona``."""
    fs = VirtualFS()

    for d in (
        "/bin", "/sbin", "/lib", "/usr", "/usr/bin", "/usr/sbin", "/usr/local",
        "/usr/local/bin", "/etc", "/home", "/root", "/tmp", "/opt", "/srv",
        "/var", "/var/log", "/var/www", "/var/www/html", "/run", "/proc", "/dev",
    ):
        fs.makedirs(d)

    # Per-user home directories.
    for u in persona.users:
        if u.home.startswith("/home/") or u.home == "/root":
            fs.makedirs(u.home, owner=u.name)

    # /etc
    fs.write_file("/etc/passwd", persona.passwd_file())
    fs.write_file("/etc/hostname", persona.hostname + "\n")
    fs.write_file("/etc/os-release", persona.os_release())
    fs.write_file(
        "/etc/shadow",
        # Fabricated, non-functional hashes. This is simulated data.
        "root:$6$rounds=656000$x$"
        "9f2c1e7a3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0:19700:0:99999:7:::\n"
        "ubuntu:!:19700:0:99999:7:::\n",
        owner="root",
    )
    fs.write_file(
        "/proc/version",
        f"Linux version {persona.kernel} (buildd@lcy02-amd64-073) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) "
        "#99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023\n",
    )

    # /root dotfiles + a webserver-flavoured docroot.
    fs.write_file("/root/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\n")
    fs.write_file("/root/.profile", "# ~/.profile: executed by the command interpreter for login shells.\n")
    fs.write_file(
        "/var/www/html/index.html",
        "<!DOCTYPE html>\n<html><head><title>Welcome</title></head>\n"
        "<body><h1>It works!</h1></body></html>\n",
        owner="www-data",
    )

    return fs


def build_session_state(persona_name: str, username: str = "root") -> SessionState:
    persona = get_persona(persona_name)
    fs = _seed_fs(persona)

    home = "/root" if username == "root" else f"/home/{username}"
    if not fs.is_dir(home):
        fs.makedirs(home, owner=username)

    shell = "/bin/bash"
    env = {
        "USER": username,
        "LOGNAME": username,
        "HOME": home,
        "PWD": home,
        "SHELL": shell,
        "TERM": "xterm-256color",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "en_US.UTF-8",
        "HOSTNAME": persona.hostname,
        "MAIL": f"/var/mail/{username}",
    }
    return SessionState(persona=persona, username=username, cwd=home, env=env, fs=fs)
