"""E0: per-page index of the Windows module corpus.

Walks the win-module-extractor ZIPs, splits joinedModuleContents.dmp into 4096 B pages and
writes one Parquet per ZIP in OUT/shards with:
  zip, arch_dir, os_dir, module, base_address, page_index, sha256, tlsh, ssdeep, sdhash,
  sdhash_features, entropy, zero_starts, zero_lengths (runs of 0x00 of MIN_ZERO_RUN bytes or more),
  dereloc (method or status of the module's derelocation; see dereloc.py).

The digests use the same implementations as the `dataset` database: TLSH without the "T1"
prefix and "-" when TLSH cannot compute it; sdhash without the file name (from the size
field). It is resumable: ZIPs whose shard is already written are skipped.

With DERELOC = sum-guide, sum-linear, sum-best or heuristic (see dereloc.py) the module image is
derelocated before splitting it; raw (default) leaves it as is.

Usage: python build_index.py CORPUS_DIR OUT_DIR [WORKERS] [raw|sum-guide|sum-linear|sum-best|heuristic]
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from multiprocessing import Pool

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep
import tlsh

from dereloc import METHODS, dereloc

PAGE = 4096
MIN_ZERO_RUN = 16
SEGMENT = re.compile(r"^([0-9a-fA-F]{16})_([0-9a-fA-F]+)\.dmp$")

SCHEMA = pa.schema([
    ("zip", pa.string()),
    ("arch_dir", pa.string()),
    ("os_dir", pa.string()),
    ("module", pa.string()),
    ("base_address", pa.uint64()),
    ("page_index", pa.int32()),
    ("sha256", pa.binary(32)),
    ("tlsh", pa.string()),
    ("ssdeep", pa.string()),
    ("sdhash", pa.string()),
    ("sdhash_features", pa.int32()),
    ("entropy", pa.float32()),
    ("zero_starts", pa.list_(pa.int16())),
    ("zero_lengths", pa.list_(pa.int16())),
    ("dereloc", pa.string()),
])


def tlsh_digest(page):
    h = tlsh.hash(page)
    if not h or h == "TNULL":
        return "-"
    return h[2:] if h.startswith("T1") else h


def sdhash_digests(pages, tmp):
    """sdhash digests of all pages of a ZIP with a single invocation of the binary."""
    for i, page in enumerate(pages):
        with open(os.path.join(tmp, f"{i:07d}"), "wb") as fh:
            fh.write(page)
    out = subprocess.run(["sdhash", "-r", "-p", "1", tmp], capture_output=True, text=True, check=True).stdout
    digests = [None] * len(pages)
    for line in out.splitlines():
        fields = line.split(":")
        # sdbf:03:<name length>:<name>:<size>:...
        name_len = int(fields[2])
        rest = line[len("sdbf:03:") + len(fields[2]) + 1:]
        name, tail = rest[:name_len], rest[name_len + 1:]
        digests[int(os.path.basename(name))] = tail
    return digests


def sdhash_features(tail):
    # <size>:sha1:256:5:7ff:160:<no. of filters>:<elements in the last filter>:...
    f = tail.split(":")
    return (int(f[6]) - 1) * int(f[5]) + int(f[7])


def entropy(page):
    counts = np.bincount(np.frombuffer(page, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / PAGE
    return float(-(p * np.log2(p)).sum())


def zero_runs(page):
    arr = np.frombuffer(page, dtype=np.uint8) == 0
    edges = np.diff(np.concatenate(([0], arr.view(np.int8), [0])))
    starts = np.flatnonzero(edges == 1)
    lengths = np.flatnonzero(edges == -1) - starts
    keep = lengths >= MIN_ZERO_RUN
    return starts[keep].astype(np.int16).tolist(), lengths[keep].astype(np.int16).tolist()


def index_zip(job):
    corpus, rel, out, mode = job
    shard = os.path.join(out, "shards", rel.replace("/", "__") + ".parquet")
    if os.path.exists(shard):
        return rel, "existente", 0
    parts = rel.split("/")
    arch_dir, os_dir = parts[0], parts[1]
    module = os.path.basename(rel).split("_")[0]
    try:
        with zipfile.ZipFile(os.path.join(corpus, rel)) as z:
            names = z.namelist()
            bases = [int(m.group(1), 16) for n in names if (m := SEGMENT.match(n))]
            joined = z.read("joinedModuleContents.dmp")
    except (zipfile.BadZipFile, KeyError) as exc:
        return rel, f"error: {exc!r}", 0
    base = min(bases) if bases else 0
    if mode == "raw":
        dereloc_status = "raw"
    else:
        joined, dereloc_status = dereloc(joined, base, mode, arch_dir)
    pages = [joined[i:i + PAGE] for i in range(0, len(joined) - PAGE + 1, PAGE)]
    with tempfile.TemporaryDirectory(dir=os.path.join(out, "tmp")) as tmp:
        sd = sdhash_digests(pages, tmp) if pages else []
    rows = {k: [] for k in SCHEMA.names}
    for i, page in enumerate(pages):
        zs, zl = zero_runs(page)
        rows["zip"].append(rel)
        rows["arch_dir"].append(arch_dir)
        rows["os_dir"].append(os_dir)
        rows["module"].append(module)
        rows["base_address"].append(base)
        rows["page_index"].append(i)
        rows["sha256"].append(hashlib.sha256(page).digest())
        rows["tlsh"].append(tlsh_digest(page))
        rows["ssdeep"].append(ssdeep.hash(page))
        rows["sdhash"].append(sd[i])
        rows["sdhash_features"].append(sdhash_features(sd[i]) if sd[i] else None)
        rows["entropy"].append(entropy(page))
        rows["zero_starts"].append(zs)
        rows["zero_lengths"].append(zl)
        rows["dereloc"].append(dereloc_status)
    tmp_shard = shard + ".part"
    pq.write_table(pa.table(rows, schema=SCHEMA), tmp_shard, compression="zstd")
    os.replace(tmp_shard, shard)
    return rel, "ok", len(pages)


def main():
    corpus, out = sys.argv[1], sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    mode = sys.argv[4] if len(sys.argv) > 4 else "raw"
    if mode != "raw" and mode not in METHODS:
        sys.exit(f"Modo de desreubicación desconocido: {mode}")
    os.makedirs(os.path.join(out, "shards"), exist_ok=True)
    os.makedirs(os.path.join(out, "tmp"), exist_ok=True)
    zips = []
    for dirpath, _, files in os.walk(corpus):
        for f in files:
            if f.endswith(".zip"):
                full = os.path.join(dirpath, f)
                zips.append((os.path.getsize(full), os.path.relpath(full, corpus)))
    zips.sort(reverse=True)  # largest first, to balance the load
    jobs = [(corpus, rel, out, mode) for _, rel in zips]
    done = pages = errors = 0
    with Pool(workers) as pool, open(os.path.join(out, "build_index.log"), "a") as log:
        for rel, status, n in pool.imap_unordered(index_zip, jobs, chunksize=4):
            done += 1
            pages += n
            if status.startswith("error"):
                errors += 1
                log.write(f"{rel}\t{status}\n")
            if done % 500 == 0 or done == len(jobs):
                print(f"{done}/{len(jobs)} ZIP, {pages} páginas nuevas, {errors} errores", flush=True)
    print(f"Hecho: {len(jobs)} ZIP, {pages} páginas nuevas, {errors} errores")


if __name__ == "__main__":
    main()
