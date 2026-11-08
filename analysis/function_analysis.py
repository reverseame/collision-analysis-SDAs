"""Function-level complement to E8.

Radare2 JSON files (one per PE) give each function's virtual address and size, and store at most
500 bytes of its body. A function is contiguous when its full body is stored and equals the file
slice; its prefix is verified when the stored bytes (possibly truncated) equal the start of that
slice. Radare also reports ranges of up to 12.6 MB that are not single functions; ranges above
MAX_FUNCTION bytes are treated as implausible.

Phases:
  index     function ranges for the E8 pool and symbol-named functions for drift
  overlap   whether E8 code caves and shellcode writes fall inside a function
  drift     legitimate drift of the same symbol across the E8 version transitions
  preserve  16-byte shellcode forced inside a function, at the start and at a random offset

Usage:
  python function_analysis.py index JSON_ROOT PE_ROOT E8_POOL OUT WORKERS
  python function_analysis.py overlap E8_POOL E8_TRIALS OUT
  python function_analysis.py drift OUT PE_ROOT WORKERS
  python function_analysis.py preserve OUT PE_ROOT WORKERS
"""
import glob
import hashlib
import json
import os
import random
import re
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd
import pefile
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep

from pe_drift_baseline import TRANSITIONS
from preservation_margin import SHELLCODE, stable_rng, wilson
from sda_common import (
    MIN_SDHASH_FEATURES,
    full_sdbf,
    sdhash_features,
    sdhash_files,
    sdhash_scores,
    tlsh_digest,
    tlsh_distance,
)

ARCHITECTURES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "arm", 0xAA64: "arm64"}
EXPORT = re.compile(r"^sym\.(?!imp\.)(?:[^.]+\.(?:dll|exe|sys)_)?(.+)$", re.IGNORECASE)
MACHINE = re.compile(r"maquina(\d+)/")
SAMPLE_PER_BUCKET = 200
PAYLOAD = 16
SDHASH_MIN_BYTES = 512  # sdhash 3.4 emits no digest below this size
MAX_FUNCTION = 8192  # larger radare ranges span several functions or whole sections
SEED = 20261029


def pe_relative(file_field):
    match = MACHINE.search(file_field.replace("\\", "/"))
    if not match:
        return None
    return file_field.replace("\\", "/")[match.start():]


def index_one(args):
    json_path, pe_root, pool_paths = args
    try:
        document = json.load(open(json_path))
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"{json_path}\t{type(exc).__name__}: {exc}"}, [], []
    relative = pe_relative(str(document.get("file", "")))
    if relative is None:
        return {"error": f"{json_path}\tbad_path"}, [], []
    pe_path = os.path.join(pe_root, relative)
    if not os.path.isfile(pe_path):
        return {"missing": relative}, [], []
    with open(pe_path, "rb") as handle:
        raw = handle.read()
    try:
        image = pefile.PE(data=raw, fast_load=True)
    except pefile.PEFormatError as exc:
        return {"error": f"{relative}\t{exc}"}, [], []
    base = int(image.OPTIONAL_HEADER.ImageBase)
    architecture = ARCHITECTURES.get(image.FILE_HEADER.Machine, f"machine_{image.FILE_HEADER.Machine:04x}")
    machine = int(MACHINE.search(relative).group(1))
    kind = os.path.splitext(relative)[1][1:].lower()
    module = os.path.basename(relative).lower()
    wanted = relative in pool_paths
    ranges, exports = [], []
    for key, function in document.items():
        if not isinstance(function, dict) or "offset" not in function or "size" not in function:
            continue
        size = int(function["size"])
        if size <= 0 or key == "entry0":
            continue
        rva = int(function["offset"]) - base
        try:
            file_offset = image.get_offset_from_rva(rva)
        except Exception:
            file_offset = None
        if file_offset is None:
            continue
        stored = function.get("bytes") or ""
        prefix = b""
        try:
            prefix = bytes.fromhex(stored)
            prefix_verified = bool(prefix) and image.get_data(rva, len(prefix)) == prefix
        except Exception:
            prefix_verified = False
        contiguous = prefix_verified and len(prefix) == size
        row = {
            "path": relative, "machine": machine, "architecture": architecture, "kind": kind,
            "module": module, "func": key, "file_offset": int(file_offset), "size": size,
            "contiguous": contiguous, "prefix_verified": prefix_verified,
        }
        if wanted:
            ranges.append(row)
        match = EXPORT.match(key)
        if match and contiguous and size >= 50:
            digest = hashlib.sha256(prefix).digest()
            exports.append({
                **row,
                "export": match.group(1).lower(),
                "sha256": digest,
            })
    return {"json": 1, "ranges": len(ranges), "exports": len(exports)}, ranges, exports


def write_shard(directory, name, rows):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    if not rows:
        return
    temporary = path + ".part"
    pq.write_table(pa.Table.from_pylist(rows), temporary, compression="zstd")
    os.replace(temporary, path)


def index(json_root, pe_root, pool_path, out, workers):
    os.makedirs(out, exist_ok=True)
    pool = set(pq.read_table(pool_path, columns=["artifact_id"]).column("artifact_id").to_pylist())
    done_path = os.path.join(out, "indexed.txt")
    done = set(open(done_path).read().splitlines()) if os.path.exists(done_path) else set()
    pending = []
    for dirpath, _dirs, names in os.walk(json_root):
        for name in names:
            if name.endswith(".json"):
                path = os.path.join(dirpath, name)
                if path not in done:
                    pending.append(path)
    pending.sort()
    print(f"JSON pendientes: {len(pending)} | ya indexados: {len(done)} | PE del pool: {len(pool)}", flush=True)
    totals = {"json": 0, "ranges": 0, "exports": 0, "missing": 0, "errors": 0}
    batch = 100
    with ProcessPoolExecutor(max_workers=workers) as executor, open(done_path, "a") as done_file:
        for start in range(0, len(pending), batch):
            chunk = pending[start:start + batch]
            ranges, exports, errors = [], [], []
            for result, range_rows, export_rows in executor.map(
                index_one, ((path, pe_root, pool) for path in chunk), chunksize=1
            ):
                totals["json"] += result.get("json", 0)
                totals["ranges"] += result.get("ranges", 0)
                totals["exports"] += result.get("exports", 0)
                totals["missing"] += 1 if "missing" in result else 0
                if "error" in result:
                    totals["errors"] += 1
                    errors.append(result["error"])
                ranges.extend(range_rows)
                exports.extend(export_rows)
            stamp = f"{start:06d}"
            write_shard(os.path.join(out, "ranges"), f"{stamp}.parquet", ranges)
            write_shard(os.path.join(out, "exports"), f"{stamp}.parquet", exports)
            if errors:
                with open(os.path.join(out, "errors.tsv"), "a") as handle:
                    handle.write("\n".join(errors) + "\n")
            done_file.write("\n".join(chunk) + "\n")
            done_file.flush()
            print(f"  {min(start + batch, len(pending))}/{len(pending)} {totals}", flush=True)
    print(f"índice: {totals}", flush=True)


def load_shards(out, kind):
    files = sorted(glob.glob(os.path.join(out, kind, "*.parquet")))
    if not files:
        raise SystemExit(f"No hay {kind} en {out}")
    return pa.concat_tables([pq.read_table(path) for path in files]).to_pandas()


def intersects(start, length, ranges):
    end = start + length
    for left, right in ranges:
        if left < end and right > start:
            return True
    return False


def overlap(pool_path, trials_dir, out):
    pool = pq.read_table(pool_path).to_pandas()
    ranges = load_shards(out, "ranges")
    trials = pd.read_parquet(trials_dir)
    trials = trials[(trials.placement == "code_cave") & (trials.content == "shellcode") & (trials.changed == True)]  # noqa: E712
    variants = {
        "all_ranges": ranges,
        "plausible": ranges[ranges["size"] <= MAX_FUNCTION],
        "contiguous": ranges[ranges.contiguous],
    }
    rows = []
    for name, frame in variants.items():
        by_path = {
            path: list(zip(group.file_offset.astype(int), (group.file_offset + group["size"]).astype(int)))
            for path, group in frame.groupby("path")
        }
        covered = pool[pool.artifact_id.isin(by_path)]
        runs = inside = cave_bytes = inside_bytes = 0
        for record in covered.itertuples(index=False):
            function_ranges = by_path[record.artifact_id]
            for start, length in zip(record.cave_starts, record.cave_lengths):
                hit = intersects(int(start), int(length), function_ranges)
                runs += 1
                inside += hit
                cave_bytes += int(length)
                inside_bytes += int(length) * hit
        writes = trials[trials.artifact_id.isin(by_path)]
        writes_inside = sum(
            intersects(int(row.offset), int(row.write_size), by_path[row.artifact_id])
            for row in writes.itertuples(index=False)
        )
        rows.append({
            "ranges": name, "pool_pe": len(pool), "pe_with_functions": len(covered),
            "cave_runs": runs, "cave_runs_inside_function": inside,
            "cave_bytes": cave_bytes, "cave_bytes_inside_function": inside_bytes,
            "shellcode_writes": len(writes), "shellcode_writes_inside_function": int(writes_inside),
        })
    summary = pd.DataFrame(rows)
    summary.to_csv(os.path.join(out, "overlap.csv"), index=False)
    print(summary.to_string(index=False), flush=True)


def hash_unique(frame, pe_root, workers):
    keys = frame[["path", "file_offset", "size"]].drop_duplicates()
    digests = {}
    paths, blobs = [], []
    temporary = tempfile.mkdtemp(prefix="fn-hash-")
    try:
        for number, record in enumerate(keys.itertuples(index=False)):
            with open(os.path.join(pe_root, record.path), "rb") as handle:
                handle.seek(int(record.file_offset))
                data = handle.read(int(record.size))
            key = (record.path, int(record.file_offset), int(record.size))
            digests[key] = {
                "tlsh": tlsh_digest(data),
                "ssdeep": ssdeep.hash(data),
                "sdhash": None,
                "sdhash_features": 0,
            }
            if len(data) < SDHASH_MIN_BYTES:
                continue
            path = os.path.join(temporary, f"{number:07d}")
            with open(path, "wb") as handle:
                handle.write(data)
            paths.append(path)
            blobs.append(key)
            if len(paths) == 2000:
                _flush_sdhash(digests, paths, blobs, workers)
                paths, blobs = [], []
                print(f"  hasheadas {number + 1}/{len(keys)}", flush=True)
        if paths:
            _flush_sdhash(digests, paths, blobs, workers)
        print(f"  hasheadas {len(keys)}/{len(keys)}", flush=True)
    finally:
        for name in os.listdir(temporary):
            os.remove(os.path.join(temporary, name))
        os.rmdir(temporary)
    return digests


def _flush_sdhash(digests, paths, blobs, workers):
    for key, digest in zip(blobs, sdhash_files(paths, workers, include_scheme=True)):
        digests[key]["sdhash"] = digest
        digests[key]["sdhash_features"] = sdhash_features(digest)
    for path in paths:
        os.remove(path)
    return digests


def attach(frame, digests, suffix):
    rows = []
    for record in frame.itertuples(index=False):
        found = digests[(record.path, int(record.file_offset), int(record.size))]
        rows.append({f"{name}_{suffix}": value for name, value in found.items()})
    return pd.concat([frame.reset_index(drop=True), pd.DataFrame(rows)], axis=1)


def thresholds_of(pairs):
    rows = []
    for subset, mask in (("todos", np.ones(len(pairs), dtype=bool)), ("no_identicos", ~pairs.identical.to_numpy())):
        for algorithm, column, higher in (("ssdeep", "ssdeep_score", True), ("tlsh", "tlsh_dist", False), ("sdhash", "sdhash_score", True)):
            values = pairs.loc[mask, column].dropna().to_numpy()
            row = {
                "pares": subset, "algoritmo": algorithm, "n": len(values),
                "comparables_%": 100 * len(values) / max(1, int(mask.sum())),
                "mediana": np.median(values) if len(values) else np.nan,
            }
            for acceptance in (90, 95, 99):
                percentile = 100 - acceptance if higher else acceptance
                row[f"tau_{acceptance}"] = np.percentile(values, percentile) if len(values) else np.nan
            rows.append(row)
    return pd.DataFrame(rows)


def drift(out, pe_root, workers):
    exports = load_shards(out, "exports")
    counts = exports.groupby(["machine", "architecture", "kind", "module", "export"]).size()
    ambiguous = counts[counts > 1]
    key = ["machine", "architecture", "kind", "module", "export"]
    bad = pd.MultiIndex.from_frame(exports[key]).isin(ambiguous.index)
    print(f"export duplicados excluidos: {int(bad.sum())}", flush=True)
    exports = exports[~bad]
    parts = []
    for left_machine, right_machine, transition in TRANSITIONS:
        left = exports[exports.machine == left_machine]
        right = exports[exports.machine == right_machine]
        paired = left.merge(right, on=["architecture", "kind", "module", "export"], suffixes=("_a", "_b"))
        paired["transition"] = transition
        parts.append(paired)
        print(f"  {transition}: {len(paired)} pares", flush=True)
    pairs = pd.concat(parts, ignore_index=True)
    unique = pd.concat([
        pairs[["path_a", "file_offset_a", "size_a"]].rename(columns={"path_a": "path", "file_offset_a": "file_offset", "size_a": "size"}),
        pairs[["path_b", "file_offset_b", "size_b"]].rename(columns={"path_b": "path", "file_offset_b": "file_offset", "size_b": "size"}),
    ]).drop_duplicates()
    print(f"funciones distintas a hashear: {len(unique)}", flush=True)
    digests = hash_unique(unique, pe_root, workers)
    left = attach(pairs[["path_a", "file_offset_a", "size_a"]].rename(
        columns={"path_a": "path", "file_offset_a": "file_offset", "size_a": "size"}), digests, "a")
    right = attach(pairs[["path_b", "file_offset_b", "size_b"]].rename(
        columns={"path_b": "path", "file_offset_b": "file_offset", "size_b": "size"}), digests, "b")
    scored = pairs[["transition", "architecture", "kind", "module", "export", "size_a", "size_b", "sha256_a", "sha256_b"]].copy()
    scored["identical"] = pairs.sha256_a == pairs.sha256_b
    scored["ssdeep_score"] = [ssdeep.compare(a, b) for a, b in zip(left.ssdeep_a, right.ssdeep_b)]
    scored["tlsh_dist"] = [tlsh_distance(a, b) for a, b in zip(left.tlsh_a, right.tlsh_b)]
    comparable = (left.sdhash_features_a >= MIN_SDHASH_FEATURES) & (right.sdhash_features_b >= MIN_SDHASH_FEATURES)
    scored["sdhash_score"] = np.nan
    lines = [f"{full_sdbf(a)}\t{full_sdbf(b)}" for a, b in zip(left.loc[comparable, "sdhash_a"], right.loc[comparable, "sdhash_b"])]
    if lines:
        scored.loc[comparable, "sdhash_score"] = sdhash_scores(lines, workers)
    pq.write_table(pa.Table.from_pandas(scored, preserve_index=False), os.path.join(out, "drift_pairs.parquet"), compression="zstd")
    thresholds = thresholds_of(scored)
    thresholds.to_csv(os.path.join(out, "drift_thresholds.csv"), index=False)
    print(f"pares: {len(scored)} | idénticos: {int(scored.identical.sum())} ({100 * scored.identical.mean():.1f} %)", flush=True)
    print(thresholds.to_string(index=False, float_format=lambda value: f"{value:.1f}"), flush=True)


def preserve(out, pe_root, workers):
    """16-byte shellcode inside functions of the E8 pool.

    Up to 500 bytes, functions must be contiguous (whole body stored and equal to the file). Above
    that the stored body is truncated, so the function is hashed from the file range radare
    reports, provided the stored prefix matches the file and the range is plausible. Mutants are
    also scored against the function-drift thresholds (run 'drift' first).
    """
    source = load_shards(out, "ranges")
    small = source[source.contiguous & (source["size"] >= 50)].copy()
    small["bucket"] = np.where(small["size"] >= 256, "256-500", "50-255")
    large = source[
        source.prefix_verified & (source["size"] >= SDHASH_MIN_BYTES) & (source["size"] <= MAX_FUNCTION)
    ].copy()
    large["bucket"] = "512-8192"
    eligible = pd.concat([small, large], ignore_index=True)
    drift_thresholds = pd.read_csv(os.path.join(out, "drift_thresholds.csv"))
    drift_thresholds = drift_thresholds[drift_thresholds.pares == "todos"].set_index("algoritmo")
    rng = random.Random(SEED)
    chosen = []
    for (_arch, _bucket), group in eligible.groupby(["architecture", "bucket"]):
        positions = list(group.index)
        rng.shuffle(positions)
        chosen.extend(positions[:SAMPLE_PER_BUCKET])
    sample = eligible.loc[chosen]
    print(f"funciones muestreadas: {len(sample)}", flush=True)
    rows, mutant_paths, original_paths = [], [], []
    temporary = tempfile.mkdtemp(prefix="fn-preserve-")
    try:
        for number, record in enumerate(sample.itertuples(index=False)):
            with open(os.path.join(pe_root, record.path), "rb") as handle:
                handle.seek(int(record.file_offset))
                original = handle.read(int(record.size))
            original_path = os.path.join(temporary, f"orig_{number:07d}")
            with open(original_path, "wb") as handle:
                handle.write(original)
            original_paths.append(original_path)
            original_ssdeep, original_tlsh = ssdeep.hash(original), tlsh_digest(original)
            local = stable_rng(SEED, record.path, record.file_offset, record.func)
            for placement, offset in (
                ("start", 0),
                ("interior", int(local.integers(0, len(original) - PAYLOAD + 1))),
            ):
                mutant = bytearray(original)
                mutant[offset:offset + PAYLOAD] = (SHELLCODE * 2)[:PAYLOAD]
                mutant = bytes(mutant)
                path = os.path.join(temporary, f"mut_{len(mutant_paths):07d}")
                with open(path, "wb") as handle:
                    handle.write(mutant)
                mutant_paths.append(path)
                rows.append({
                    "path": record.path, "func": record.func, "architecture": record.architecture,
                    "bucket": record.bucket, "size": int(record.size), "placement": placement,
                    "changed_bytes": sum(left != right for left, right in zip(original, mutant)),
                    "ssdeep_score": ssdeep.compare(original_ssdeep, ssdeep.hash(mutant)),
                    "ssdeep_exact": original_ssdeep == ssdeep.hash(mutant),
                    "tlsh_dist": tlsh_distance(original_tlsh, tlsh_digest(mutant)),
                    "tlsh_exact": original_tlsh == tlsh_digest(mutant) and original_tlsh != "-",
                    "original_index": number,
                })
        original_sdhash = {}
        long_originals = [path for path in original_paths if os.path.getsize(path) >= SDHASH_MIN_BYTES]
        long_mutants = [path for path in mutant_paths if os.path.getsize(path) >= SDHASH_MIN_BYTES]
        if long_originals:
            for path, digest in zip(long_originals, sdhash_files(long_originals, workers, include_scheme=True)):
                original_sdhash[path] = digest
        mutant_by_path = {}
        if long_mutants:
            for path, digest in zip(long_mutants, sdhash_files(long_mutants, workers, include_scheme=True)):
                mutant_by_path[path] = digest
        lines, indexes = [], []
        for index, row in enumerate(rows):
            original = original_sdhash.get(original_paths[row["original_index"]])
            mutant = mutant_by_path.get(mutant_paths[index])
            row["original_sdhash_features"] = sdhash_features(original) if original else 0
            row["mutant_sdhash_features"] = sdhash_features(mutant) if mutant else 0
            row["sdhash_exact"] = original is not None and original == mutant
            if row["original_sdhash_features"] >= MIN_SDHASH_FEATURES and row["mutant_sdhash_features"] >= MIN_SDHASH_FEATURES:
                lines.append(f"{full_sdbf(original)}\t{full_sdbf(mutant)}")
                indexes.append(index)
                row["sdhash_comparable"] = True
            else:
                row["sdhash_comparable"] = False
                row["sdhash_score"] = None
        for index, score in zip(indexes, sdhash_scores(lines, workers)):
            rows[index]["sdhash_score"] = score
    finally:
        for name in os.listdir(temporary):
            os.remove(os.path.join(temporary, name))
        os.rmdir(temporary)
    frame = pd.DataFrame(rows).drop(columns=["original_index"])
    pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), os.path.join(out, "preserve.parquet"), compression="zstd")
    summary = []
    for (bucket, placement), group in frame.groupby(["bucket", "placement"]):
        comparable = group[group.sdhash_comparable]
        tlsh = group[group.tlsh_dist.notna()]
        summary.append({
            "bucket": bucket, "placement": placement, "functions": len(group),
            "median_changed": group.changed_bytes.median(),
            "ssdeep_exact": int(group.ssdeep_exact.sum()), "ssdeep_median": group.ssdeep_score.median(),
            "ssdeep_drift_tau95": int((group.ssdeep_score >= drift_thresholds.loc["ssdeep", "tau_95"]).sum()),
            "tlsh_comparable": len(tlsh), "tlsh_exact": int(tlsh.tlsh_exact.sum()) if len(tlsh) else 0,
            "tlsh_median": tlsh.tlsh_dist.median() if len(tlsh) else np.nan,
            "tlsh_drift_tau95": int((tlsh.tlsh_dist <= drift_thresholds.loc["tlsh", "tau_95"]).sum()),
            "sdhash_comparable": len(comparable),
            "sdhash_score_100": int((comparable.sdhash_score == 100).sum()) if len(comparable) else 0,
            "sdhash_exact": int(comparable.sdhash_exact.sum()) if len(comparable) else 0,
            "sdhash_median": comparable.sdhash_score.median() if len(comparable) else np.nan,
        })
    result = pd.DataFrame(summary)
    result.to_csv(os.path.join(out, "preserve.csv"), index=False)
    print(result.to_string(index=False), flush=True)


def main():
    command = sys.argv[1]
    if command == "index":
        json_root, pe_root, pool, out = sys.argv[2:6]
        workers = int(sys.argv[6]) if len(sys.argv) > 6 else os.cpu_count()
        index(json_root, pe_root, pool, out, workers)
    elif command == "overlap":
        overlap(sys.argv[2], sys.argv[3], sys.argv[4])
    elif command == "drift":
        drift(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else os.cpu_count())
    elif command == "preserve":
        preserve(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else os.cpu_count())
    else:
        raise SystemExit(f"fase desconocida: {command}")


if __name__ == "__main__":
    main()
