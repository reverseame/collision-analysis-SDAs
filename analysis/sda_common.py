"""Shared digest and scoring helpers for E1, E3 and E8."""
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import ssdeep
import tlsh

MIN_SDHASH_FEATURES = 16


def tlsh_digest(data):
    digest = tlsh.hash(data)
    if not digest or digest == "TNULL":
        return "-"
    return digest[2:] if digest.startswith("T1") else digest


def sdhash_features(digest):
    """Return the number of selected features from a tail or normalized full SDBF.

    sdbf:    <size>:sha1:256:5:7ff:160:<filters>:<last filter count>:<data>
    sdbf-dd: <size>:sha1:256:5:7ff:192:<filters>:<dd block size>:(<count hex>:<filter>)*
    """
    if not digest:
        return 0
    dd = digest.startswith("sdbf-dd:")
    if digest.startswith(("sdbf:", "sdbf-dd:")):
        header = digest.split(":", 3)
        name_len = int(header[2])
        digest = header[3][name_len + 1:]
    fields = digest.split(":")
    if dd:
        return sum(int(count, 16) for count in fields[8::2])
    return (int(fields[6]) - 1) * int(fields[5]) + int(fields[7])


def parse_sdhash_line(line, include_scheme=False):
    fields = line.split(":", 3)
    if len(fields) != 4 or fields[0] not in {"sdbf", "sdbf-dd"} or fields[1] != "03":
        raise ValueError(f"Salida de sdhash no reconocida: {line[:120]!r}")
    scheme = fields[0]
    name_len = int(fields[2])
    rest = fields[3]
    name = rest[:name_len]
    if len(rest) <= name_len or rest[name_len] != ":":
        raise ValueError(f"Longitud de nombre inválida en salida de sdhash: {line[:120]!r}")
    tail = rest[name_len + 1:]
    return name, f"{scheme}:03:0::{tail}" if include_scheme else tail


def sdhash_files(paths, workers=1, include_scheme=False):
    """Hash paths in one sdhash invocation; return tails or normalized full SDBFs in input order."""
    paths = [os.fspath(path) for path in paths]
    if not paths:
        return []
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as names:
        names.write("\n".join(paths) + "\n")
        names.flush()
        proc = subprocess.run(
            ["sdhash", "-z", "2048", "-p", str(max(1, workers)), "-f", names.name],
            capture_output=True,
            text=True,
            check=True,
        )
    by_name = dict(parse_sdhash_line(line, include_scheme) for line in proc.stdout.splitlines() if line)
    missing = [path for path in paths if path not in by_name]
    if missing:
        raise RuntimeError(f"sdhash no devolvió {len(missing)} de {len(paths)} ficheros; primero: {missing[0]}")
    return [by_name[path] for path in paths]


def sdhash_scores(lines, workers=1):
    """Score full-SDBF pairs with sdhash-pairs, preserving input order."""
    if not lines:
        return []
    chunks = np.array_split(np.asarray(lines, dtype=object), max(1, workers))

    def run(chunk):
        if len(chunk) == 0:
            return []
        proc = subprocess.run(
            ["sdhash-pairs"],
            input="\n".join(chunk) + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        return [int(value) for value in proc.stdout.split()]

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return [score for part in pool.map(run, chunks) for score in part]


def ssdeep_score(left, right):
    return ssdeep.compare(left, right)


def tlsh_distance(left, right):
    if left == "-" or right == "-":
        return None
    return tlsh.diff("T1" + left, "T1" + right)


def full_sdbf(digest):
    if digest.startswith(("sdbf:", "sdbf-dd:")):
        return digest
    return "sdbf:03:0::" + digest
