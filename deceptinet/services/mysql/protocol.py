"""Minimal MySQL client/server wire-protocol helpers (Phase 3).

Implements just enough of the protocol for a believable handshake, credential
capture, and COM_QUERY result sets (text protocol, ProtocolText::Resultset with
EOF packets — we do NOT advertise CLIENT_DEPRECATE_EOF).

NOT IMPLEMENTED (see LIMITATIONS.md): real auth verification (we accept any),
caching_sha2 negotiation, prepared statements (COM_STMT_*), SSL/TLS,
compression, multi-statement, LOCAL INFILE.
"""

from __future__ import annotations

import asyncio
import struct

# --- packet framing --------------------------------------------------------

def frame(payload: bytes, seq: int) -> bytes:
    n = len(payload)
    return bytes([n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, seq & 0xFF]) + payload


async def read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await reader.readexactly(4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    payload = await reader.readexactly(length) if length else b""
    return seq, payload


# --- length-encoded primitives --------------------------------------------

def lenenc_int(n: int) -> bytes:
    if n < 0xFB:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfc" + struct.pack("<H", n)
    if n <= 0xFFFFFF:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def lenenc_str(s: str | bytes) -> bytes:
    b = s.encode("utf-8", "replace") if isinstance(s, str) else s
    return lenenc_int(len(b)) + b


# --- packets ---------------------------------------------------------------

def build_handshake(connection_id: int, server_version: str = "8.0.35", salt: bytes = b"") -> bytes:
    if len(salt) < 20:
        salt = (salt + b"\x01" * 20)[:20]
    capabilities = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000  # long_pw|proto41|secure|plugin_auth
    cap_lower = capabilities & 0xFFFF
    cap_upper = (capabilities >> 16) & 0xFFFF
    payload = bytearray()
    payload += b"\x0a"  # protocol version 10
    payload += server_version.encode("ascii") + b"\x00"
    payload += struct.pack("<I", connection_id)
    payload += salt[:8]              # auth-plugin-data-part-1
    payload += b"\x00"              # filler
    payload += struct.pack("<H", cap_lower)
    payload += b"\x21"             # charset utf8_general_ci (33)
    payload += struct.pack("<H", 0x0002)  # status flags (autocommit)
    payload += struct.pack("<H", cap_upper)
    payload += bytes([21])          # length of auth-plugin-data (plugin_auth set)
    payload += b"\x00" * 10        # reserved
    payload += salt[8:20] + b"\x00"  # auth-plugin-data-part-2 (13 bytes)
    payload += b"mysql_native_password\x00"
    return bytes(payload)


def parse_handshake_response(payload: bytes) -> str:
    """Best-effort extraction of the username from a HandshakeResponse41."""
    # 4 caps + 4 max_packet + 1 charset + 23 reserved = 32 bytes, then NUL-term user.
    if len(payload) <= 32:
        return ""
    rest = payload[32:]
    nul = rest.find(b"\x00")
    if nul == -1:
        return rest.decode("utf-8", "replace")
    return rest[:nul].decode("utf-8", "replace")


def ok_packet() -> bytes:
    return b"\x00" + lenenc_int(0) + lenenc_int(0) + struct.pack("<H", 0x0002) + struct.pack("<H", 0)


def eof_packet() -> bytes:
    return b"\xfe" + struct.pack("<H", 0) + struct.pack("<H", 0x0002)


def err_packet(code: int, message: str, sqlstate: str = "HY000") -> bytes:
    return b"\xff" + struct.pack("<H", code) + b"#" + sqlstate.encode("ascii") + message.encode("utf-8", "replace")


def _column_def(name: str) -> bytes:
    p = bytearray()
    p += lenenc_str("def")   # catalog
    p += lenenc_str("")      # schema
    p += lenenc_str("")      # table
    p += lenenc_str("")      # org_table
    p += lenenc_str(name)    # name
    p += lenenc_str("")      # org_name
    p += bytes([0x0c])       # length of fixed fields
    p += struct.pack("<H", 0x21)   # charset
    p += struct.pack("<I", 256)    # column length
    p += bytes([0xFD])             # type = VAR_STRING
    p += struct.pack("<H", 0)      # flags
    p += bytes([0x00])             # decimals
    p += b"\x00\x00"              # filler
    return bytes(p)


def build_result_set(columns: list[str], rows: list[list[str]]) -> list[bytes]:
    """Return the ordered list of payloads for a text result set (caller frames
    each with an incrementing sequence id)."""
    payloads: list[bytes] = [lenenc_int(len(columns))]
    payloads += [_column_def(c) for c in columns]
    payloads.append(eof_packet())
    for row in rows:
        payloads.append(b"".join(lenenc_str("" if v is None else str(v)) for v in row))
    payloads.append(eof_packet())
    return payloads
