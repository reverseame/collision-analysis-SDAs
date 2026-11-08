"""Derelocation of module images loaded in memory (virtual layout, offset = RVA).

sum-guide   SUM's guided derelocation algorithm (`guided_derelocation`, reverseame/
            similarity-unrelocated-module) applied in place on a bytearray, with the base
            relocation table (directory 5) read from the in-memory image itself: it zeroes the high
            bytes of each relocated field (+2..+3 for HIGHLOW, +2..+7 for DIR64, +0..+1 for types 1 and 2,
            +0..+3 for type 4 and unknown types) and of OptionalHeader.ImageBase. The SUM engine does the
            same by rebuilding the whole image for each entry (quadratic cost: hours on large
            modules) and fails to build MarkedPE on ~4% of 64-bit modules; this version gives the
            same bytes as the engine on the 254 checked modules where the engine finishes.
sum-linear  Linear sweep of the SUM engine (Python 3; /opt/sum in the image), unchanged.
sum-best    SUM's default criterion: guide if there is a readable .reloc and linear otherwise.
heuristic   Replaces each 4 B (PE32) or 8 B (PE32+) value that falls in [base, base + size) with its
            offset from the base, left to right and without overlaps.

Each function returns (image, status). Statuses: guide, linear, heuristic, sin_pe, sin_reloc (guide
requested but the image has no readable .reloc; unchanged except ImageBase), error_linear (the engine
failed; unchanged).
"""
import logging
import struct

import numpy as np
from derelocation import linear_sweep_derelocation
from marked_pefile.marked_pefile import MarkedPE

# marked_pefile logs a WARNING for each byte it revisits during the sweep; it does not
# affect the result and floods the output in runs over the whole corpus.
logging.getLogger().setLevel(logging.ERROR)

PE32, PE32_PLUS = 0x10B, 0x20B
DIR_BASERELOC = 5
METHODS = ("sum-guide", "sum-linear", "sum-best", "heuristic")


def parse_pe(img):
    """(is64, ImageBase offset, .reloc RVA, .reloc size), or None."""
    if len(img) < 0x40 or img[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", img, 0x3C)[0]
    if e_lfanew + 26 > len(img) or img[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", img, opt)[0]
    if magic == PE32:
        imagebase_off, dirs = opt + 28, opt + 96
    elif magic == PE32_PLUS:
        imagebase_off, dirs = opt + 24, opt + 112
    else:
        return None
    entry = dirs + DIR_BASERELOC * 8
    if entry + 8 > len(img):
        return None
    rva, size = struct.unpack_from("<II", img, entry)
    return magic == PE32_PLUS, imagebase_off, rva, size


def reloc_from_image(img, pe):
    """Bytes of .reloc as they are in memory, or None if absent or not resident."""
    _, _, rva, size = pe
    if rva == 0 or size == 0:
        return None
    reloc = img[rva:rva + size]
    return reloc if len(reloc) >= 8 and any(reloc) else None


def guide(img, pe, reloc):
    is64, imagebase_off, _, _ = pe
    out = bytearray(img)
    out[imagebase_off + 2:imagebase_off + (8 if is64 else 4)] = bytes(6 if is64 else 2)
    index = 0
    while index + 8 <= len(reloc):
        page_rva, block_size = struct.unpack_from("<II", reloc, index)
        if block_size < 8:
            break
        n = (min(block_size, len(reloc) - index) - 8) // 2
        for entry in struct.unpack_from(f"<{n}H", reloc, index + 8):
            kind, pos = entry >> 12, page_rva + (entry & 0x0FFF)
            if kind == 0 or pos >= len(out):
                continue
            if kind == 3:
                out[pos + 2:pos + 4] = b"\0\0"
            elif kind == 10:
                out[pos + 2:pos + 8] = bytes(6)
            elif kind in (1, 2):
                out[pos:pos + 2] = b"\0\0"
            else:
                out[pos:pos + 4] = bytes(4)
        index += block_size
    return bytes(out[:len(img)])


def linear(img, base):
    try:
        pe = MarkedPE(data=img, virtual_layout=True, base_address=base)
        linear_sweep_derelocation(pe)
        out = bytes(pe.__data__)
    except Exception:  # the SUM engine raises several of its own exception types and pefile's
        return img, "error_linear"
    return (out, "linear") if len(out) == len(img) else (img, "error_linear")


def heuristic(img, base, is64):
    width = 8 if is64 else 4
    if len(img) < width:
        return img, "heuristic"
    a = np.frombuffer(img, dtype=np.uint8).astype(np.uint64)
    n = len(img) - width + 1
    vals = np.zeros(n, dtype=np.uint64)
    for k in range(width):
        vals |= a[k:k + n] << np.uint64(8 * k)
    hits = np.flatnonzero((vals >= np.uint64(base)) & (vals < np.uint64(base + len(img))))
    out = bytearray(img)
    fmt = "<Q" if is64 else "<I"
    next_free = 0
    for i in hits:
        if i < next_free:
            continue
        struct.pack_into(fmt, out, int(i), int(vals[i]) - base)
        next_free = i + width
    return bytes(out), "heuristic"


def dereloc(img, base, method, arch_dir):
    pe = parse_pe(img)
    if method == "heuristic":
        return heuristic(img, base, pe[0] if pe else arch_dir == "64-bits")
    if pe is None:
        return img, "sin_pe"
    if method == "sum-linear":
        return linear(img, base)
    reloc = reloc_from_image(img, pe)
    if reloc is not None:
        return guide(img, pe, reloc), "guide"
    if method == "sum-best":
        return linear(img, base)
    return guide(img, pe, b""), "sin_reloc"
