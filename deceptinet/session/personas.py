"""Persona facts: the ground-truth "identity" of an emulated host.

Both the vanilla engine (Phase 1) and the LLM engine (Phase 2) read these so a
host presents *consistent* facts (hostname, kernel, users) regardless of mode.
Consistency across modes matters for the A/B comparison: differences in
attacker engagement should come from response *quality*, not from the vanilla
host accidentally claiming a different kernel than the LLM host.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FakeUser:
    name: str
    uid: int
    gid: int
    home: str
    shell: str
    gecos: str = ""


@dataclass(frozen=True)
class Persona:
    name: str
    hostname: str
    pretty_name: str  # e.g. "Ubuntu 22.04.3 LTS" (os-release PRETTY_NAME)
    kernel: str  # uname -r
    arch: str  # uname -m
    uname_a: str  # full `uname -a` line
    users: tuple[FakeUser, ...] = field(default_factory=tuple)

    def passwd_file(self) -> str:
        lines = []
        for u in self.users:
            lines.append(f"{u.name}:x:{u.uid}:{u.gid}:{u.gecos}:{u.home}:{u.shell}")
        return "\n".join(lines) + "\n"

    def os_release(self) -> str:
        ver = self.pretty_name
        return (
            f'PRETTY_NAME="{ver}"\n'
            'NAME="Ubuntu"\n'
            'VERSION_ID="22.04"\n'
            f'VERSION="{ver.replace("Ubuntu ", "")}"\n'
            "ID=ubuntu\n"
            "ID_LIKE=debian\n"
            "HOME_URL=\"https://www.ubuntu.com/\"\n"
        )


_UBUNTU_WEB = Persona(
    name="ubuntu-22.04-webserver",
    hostname="web-prod-01",
    pretty_name="Ubuntu 22.04.3 LTS",
    kernel="5.15.0-89-generic",
    arch="x86_64",
    uname_a=(
        "Linux web-prod-01 5.15.0-89-generic #99-Ubuntu SMP "
        "Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
    ),
    users=(
        FakeUser("root", 0, 0, "/root", "/bin/bash", "root"),
        FakeUser("daemon", 1, 1, "/usr/sbin", "/usr/sbin/nologin", "daemon"),
        FakeUser("www-data", 33, 33, "/var/www", "/usr/sbin/nologin", "www-data"),
        FakeUser("sshd", 110, 65534, "/run/sshd", "/usr/sbin/nologin", ""),
        FakeUser("ubuntu", 1000, 1000, "/home/ubuntu", "/bin/bash", "ubuntu"),
    ),
)

# A generic fallback so an unknown persona name never crashes the honeypot.
_GENERIC = Persona(
    name="generic-linux",
    hostname="server",
    pretty_name="Ubuntu 22.04.3 LTS",
    kernel="5.15.0-89-generic",
    arch="x86_64",
    uname_a=(
        "Linux server 5.15.0-89-generic #99-Ubuntu SMP "
        "Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
    ),
    users=(
        FakeUser("root", 0, 0, "/root", "/bin/bash", "root"),
        FakeUser("ubuntu", 1000, 1000, "/home/ubuntu", "/bin/bash", "ubuntu"),
    ),
)

PERSONAS: dict[str, Persona] = {
    _UBUNTU_WEB.name: _UBUNTU_WEB,
    _GENERIC.name: _GENERIC,
}


def get_persona(name: str) -> Persona:
    """Return the named persona, falling back to a generic one if unknown."""
    return PERSONAS.get(name, _GENERIC)
