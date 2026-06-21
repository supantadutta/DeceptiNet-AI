"""Virtual filesystem + session state."""

from __future__ import annotations

import pytest

from deceptinet.session.state import build_session_state
from deceptinet.session.vfs import VfsError, VirtualFS


def test_normalize():
    fs = VirtualFS()
    assert fs.normalize("foo", "/root") == "/root/foo"
    assert fs.normalize("../etc", "/root") == "/etc"
    assert fs.normalize("/abs/path", "/root") == "/abs/path"
    assert fs.normalize("", "/root") == "/root"
    assert fs.normalize(".", "/root") == "/root"


def test_mkdir_persists_and_lists():
    fs = VirtualFS()
    fs.makedirs("/root")
    fs.mkdir("/root/newdir")
    assert "newdir" in fs.listdir("/root")
    assert fs.is_dir("/root/newdir")


def test_mkdir_existing_raises():
    fs = VirtualFS()
    fs.makedirs("/root/x")
    with pytest.raises(VfsError):
        fs.mkdir("/root/x")


def test_read_write_file():
    fs = VirtualFS()
    fs.makedirs("/tmp")
    fs.write_file("/tmp/a.txt", "hello\n")
    assert fs.read("/tmp/a.txt") == "hello\n"
    with pytest.raises(VfsError):
        fs.read("/tmp/missing")


def test_remove_is_memory_only():
    fs = VirtualFS()
    fs.makedirs("/tmp")
    fs.write_file("/tmp/a.txt", "x")
    fs.remove("/tmp/a.txt")
    assert not fs.exists("/tmp/a.txt")


def test_session_state_seeded():
    st = build_session_state("ubuntu-22.04-webserver", "root")
    assert st.username == "root"
    assert st.cwd == "/root"
    assert st.is_root
    assert "root:x:0:0" in st.fs.read("/etc/passwd")
    assert st.fs.is_dir("/var/www/html")


def test_prompt_rendering():
    st = build_session_state("ubuntu-22.04-webserver", "root")
    assert st.prompt() == "root@web-prod-01:~# "
    st.cwd = "/etc"
    assert st.prompt() == "root@web-prod-01:/etc# "
