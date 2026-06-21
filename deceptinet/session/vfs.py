"""A simulated, in-memory POSIX-ish filesystem.

This is NOT a real filesystem and never touches the host disk. It exists so the
honeypot can answer ``ls`` / ``cat`` / ``cd`` / ``mkdir`` consistently within a
session. Mutations live only in process memory and die with the session.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import NamedTuple


class NodeInfo(NamedTuple):
    name: str
    is_dir: bool
    size: int
    owner: str
    mode: str


class VfsError(Exception):
    """Raised for filesystem-style errors (no such file, not a directory, ...).

    Carries an ``errno_text`` suitable for embedding in a shell-style message,
    e.g. ``"No such file or directory"``.
    """

    def __init__(self, errno_text: str) -> None:
        super().__init__(errno_text)
        self.errno_text = errno_text


@dataclass
class Node:
    name: str
    is_dir: bool
    content: str = ""
    children: dict[str, "Node"] = field(default_factory=dict)
    mode: str = "rw-r--r--"
    owner: str = "root"


class VirtualFS:
    def __init__(self) -> None:
        self.root = Node(name="/", is_dir=True, mode="rwxr-xr-x")

    # ---- path helpers -------------------------------------------------
    @staticmethod
    def normalize(path: str, cwd: str) -> str:
        """Resolve ``path`` against ``cwd`` into a clean absolute path."""
        if not path:
            return cwd
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        # posixpath.normpath collapses .., ., and double slashes.
        norm = posixpath.normpath(path)
        return norm or "/"

    def _resolve(self, abspath: str) -> Node:
        if abspath == "/":
            return self.root
        node = self.root
        for part in abspath.strip("/").split("/"):
            if not node.is_dir:
                raise VfsError("Not a directory")
            child = node.children.get(part)
            if child is None:
                raise VfsError("No such file or directory")
            node = child
        return node

    # ---- queries ------------------------------------------------------
    def exists(self, abspath: str) -> bool:
        try:
            self._resolve(abspath)
            return True
        except VfsError:
            return False

    def is_dir(self, abspath: str) -> bool:
        try:
            return self._resolve(abspath).is_dir
        except VfsError:
            return False

    def listdir(self, abspath: str) -> list[str]:
        node = self._resolve(abspath)
        if not node.is_dir:
            raise VfsError("Not a directory")
        return sorted(node.children.keys())

    def read(self, abspath: str) -> str:
        node = self._resolve(abspath)
        if node.is_dir:
            raise VfsError("Is a directory")
        return node.content

    def stat(self, abspath: str) -> NodeInfo:
        node = self._resolve(abspath)
        size = 4096 if node.is_dir else len(node.content.encode("utf-8", "replace"))
        return NodeInfo(node.name, node.is_dir, size, node.owner, node.mode)

    # ---- mutations ----------------------------------------------------
    def makedirs(self, abspath: str, owner: str = "root") -> None:
        """Create ``abspath`` and any missing parents (like ``mkdir -p``)."""
        node = self.root
        for part in abspath.strip("/").split("/"):
            if not part:
                continue
            child = node.children.get(part)
            if child is None:
                child = Node(name=part, is_dir=True, mode="rwxr-xr-x", owner=owner)
                node.children[part] = child
            elif not child.is_dir:
                raise VfsError("Not a directory")
            node = child

    def mkdir(self, abspath: str, owner: str = "root") -> None:
        """Create a single directory; parent must exist (like ``mkdir``)."""
        parent_path, name = posixpath.split(abspath)
        parent = self._resolve(parent_path or "/")
        if not parent.is_dir:
            raise VfsError("Not a directory")
        if name in parent.children:
            raise VfsError("File exists")
        parent.children[name] = Node(name=name, is_dir=True, mode="rwxr-xr-x", owner=owner)

    def write_file(self, abspath: str, content: str, owner: str = "root") -> None:
        parent_path, name = posixpath.split(abspath)
        parent = self._resolve(parent_path or "/")
        if not parent.is_dir:
            raise VfsError("Not a directory")
        existing = parent.children.get(name)
        if existing is not None and existing.is_dir:
            raise VfsError("Is a directory")
        parent.children[name] = Node(name=name, is_dir=False, content=content, owner=owner)

    def remove(self, abspath: str) -> None:
        if abspath == "/":
            raise VfsError("Operation not permitted")
        parent_path, name = posixpath.split(abspath)
        parent = self._resolve(parent_path or "/")
        if name not in parent.children:
            raise VfsError("No such file or directory")
        del parent.children[name]
