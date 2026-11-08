"""E3/E8: similarity-preservation margin under controlled byte replacement.

E3 mutates SUM-derelocated 4 KiB pages. E8 applies the same protocol to complete PE files.
Every cell is resumable and deterministic. No-op writes are retained as invalid attempts and are
excluded from all success rates.

Placements:
  zero       inside a zero run of at least the requested size
  code_cave  inside such a run covered by an executable PE section
  uniform    uniformly random valid offset
  q1..q4     fixed start of each artifact quarter

Contents: zero, nop (0x90), int3 (0xcc), random, shellcode (the executable 16-byte PoC payload).
Outputs: pool.parquet, trials/*.parquet, attempts.csv and summary.csv.
"""
import argparse
import glob
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import zipfile

import numpy as np
import pandas as pd
import pefile
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "e0_index"))
from dereloc import dereloc  # noqa: E402
from sda_common import (  # noqa: E402
    MIN_SDHASH_FEATURES,
    full_sdbf,
    sdhash_features,
    sdhash_files,
    sdhash_scores,
    tlsh_digest,
    tlsh_distance,
)

PAGE = 4096
MIN_ZERO_RUN = 16
SEGMENT = re.compile(r"^([0-9a-fA-F]{16})_([0-9a-fA-F]+)\.dmp$")
PLACEMENTS = ("zero", "code_cave", "uniform", "q1", "q2", "q3", "q4")
CONTENTS = ("zero", "nop", "int3", "random", "shellcode")
SHELLCODE = (
    b"\xB8\x01\x00\x00\x00"  # mov eax, 1
    b"\xBB\x02\x00\x00\x00"  # mov ebx, 2
    b"\xB9\x03\x00\x00\x00\xCC"  # mov ecx, 3; int3
)
TRIAL_COLUMNS = [
    "attempted", "attempt", "artifact_id", "stratum", "architecture", "system", "kind",
    "original_size", "placement", "content", "write_size", "offset", "eligible_artifacts",
    "changed", "changed_bytes", "original_sdhash_features", "mutant_sdhash_features",
    "ssdeep_score", "tlsh_dist", "sdhash_score", "ssdeep_exact", "tlsh_exact", "sdhash_exact",
    "ssdeep_saturated", "tlsh_saturated", "sdhash_saturated", "ssdeep_tau95", "ssdeep_tau99",
    "tlsh_tau95", "tlsh_tau99", "sdhash_tau95", "sdhash_tau99",
]


def stable_rng(seed, *parts):
    material = "|".join(map(str, (seed,) + parts)).encode()
    value = int.from_bytes(hashlib.sha256(material).digest()[:8], "little")
    return np.random.default_rng(value)


def zero_runs(data):
    zeros = np.frombuffer(data, dtype=np.uint8) == 0
    edges = np.diff(np.concatenate(([0], zeros.view(np.int8), [0])))
    starts = np.flatnonzero(edges == 1)
    lengths = np.flatnonzero(edges == -1) - starts
    keep = lengths >= MIN_ZERO_RUN
    return starts[keep].astype(np.int64).tolist(), lengths[keep].astype(np.int64).tolist()


def intersect_runs(starts, lengths, intervals):
    result = []
    for start, length in zip(starts, lengths):
        end = start + length
        for interval_start, interval_end in intervals:
            left, right = max(start, interval_start), min(end, interval_end)
            if right - left >= MIN_ZERO_RUN:
                result.append((left, right - left))
    result.sort()
    return [item[0] for item in result], [item[1] for item in result]


def executable_intervals(data, memory_image):
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return []
    intervals = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        if memory_image:
            start = int(section.VirtualAddress)
            length = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        else:
            start = int(section.PointerToRawData)
            length = int(section.SizeOfRawData)
        if length > 0:
            intervals.append((start, min(len(data), start + length)))
    return intervals


def stratified_sample(frame, columns, per_stratum, seed):
    rng = stable_rng(seed, "pool")
    selected = []
    for _, group in frame.sort_values(columns + ["path"] if "path" in frame else columns + ["zip", "page_index"]).groupby(columns):
        count = min(per_stratum, len(group))
        positions = rng.choice(len(group), count, replace=False)
        selected.append(group.iloc[np.sort(positions)])
    return pd.concat(selected, ignore_index=True)


def page_pool(corpus, e0, preprocess, per_stratum, seed):
    files = sorted(glob.glob(os.path.join(e0, "shards", "*.parquet")))
    columns = [
        "zip", "arch_dir", "os_dir", "page_index", "sha256", "tlsh", "ssdeep", "sdhash",
        "sdhash_features", "dereloc",
    ]
    index = pa.concat_tables([pq.read_table(path, columns=columns) for path in files]).to_pandas()
    index = index[~index.zip.str.contains(r"\(1\)", regex=True)]
    index = index[index.dereloc.isin(["guide", "linear"])]
    selected = stratified_sample(index, ["arch_dir", "os_dir"], per_stratum, seed)
    rows = []
    for zip_name, group in selected.groupby("zip", sort=True):
        with zipfile.ZipFile(os.path.join(corpus, zip_name)) as archive:
            names = archive.namelist()
            bases = [int(match.group(1), 16) for name in names if (match := SEGMENT.match(name))]
            joined = archive.read("joinedModuleContents.dmp")
        base = min(bases) if bases else 0
        if preprocess != "raw":
            joined, status = dereloc(joined, base, preprocess, group.iloc[0].arch_dir)
            if status not in {"guide", "linear"}:
                raise RuntimeError(f"{zip_name}: desreubicación inesperada {status!r}")
        executable = executable_intervals(joined, memory_image=True)
        for record in group.itertuples(index=False):
            start = int(record.page_index) * PAGE
            data = joined[start:start + PAGE]
            if len(data) != PAGE or hashlib.sha256(data).digest() != record.sha256:
                raise RuntimeError(f"{zip_name}, página {record.page_index}: no coincide con el índice")
            zero_starts, zero_lengths = zero_runs(data)
            local_exec = [
                (max(0, left - start), min(PAGE, right - start))
                for left, right in executable
                if left < start + PAGE and right > start
            ]
            cave_starts, cave_lengths = intersect_runs(zero_starts, zero_lengths, local_exec)
            artifact_id = f"{zip_name}#{record.page_index}"
            rows.append({
                "artifact_id": artifact_id,
                "stratum": f"{record.arch_dir}|{record.os_dir}",
                "architecture": record.arch_dir,
                "system": record.os_dir,
                "kind": "page",
                "path": zip_name,
                "page_index": int(record.page_index),
                "size": PAGE,
                "data": data,
                "sha256": record.sha256,
                "tlsh": record.tlsh,
                "ssdeep": record.ssdeep,
                "sdhash": record.sdhash,
                "sdhash_features": int(record.sdhash_features),
                "zero_starts": zero_starts,
                "zero_lengths": zero_lengths,
                "cave_starts": cave_starts,
                "cave_lengths": cave_lengths,
            })
    return pd.DataFrame(rows)


def pe_pool(root, index_dir, per_stratum, seed):
    files = sorted(glob.glob(os.path.join(index_dir, "shards", "*.parquet")))
    index = pa.concat_tables([pq.read_table(path) for path in files]).to_pandas()
    selected = stratified_sample(index, ["machine", "architecture", "kind"], per_stratum, seed)
    rows = []
    for record in selected.itertuples(index=False):
        with open(os.path.join(root, record.path), "rb") as handle:
            data = handle.read()
        if hashlib.sha256(data).digest() != record.sha256:
            raise RuntimeError(f"{record.path}: no coincide con el índice PE")
        starts, lengths = zero_runs(data)
        cave_starts, cave_lengths = intersect_runs(starts, lengths, executable_intervals(data, memory_image=False))
        rows.append({
            "artifact_id": record.path,
            "stratum": f"{record.machine}|{record.architecture}|{record.kind}",
            "architecture": record.architecture,
            "system": str(record.machine),
            "kind": record.kind,
            "path": record.path,
            "page_index": None,
            "size": int(record.size),
            "sha256": record.sha256,
            "tlsh": record.tlsh,
            "ssdeep": record.ssdeep,
            "sdhash": record.sdhash,
            "sdhash_features": int(record.sdhash_features),
            "zero_starts": starts,
            "zero_lengths": lengths,
            "cave_starts": cave_starts,
            "cave_lengths": cave_lengths,
        })
    return pd.DataFrame(rows)


def load_thresholds(path):
    frame = pd.read_csv(path)
    frame = frame[frame.pares == "todos"].set_index("algoritmo")
    required = {"ssdeep", "tlsh", "sdhash"}
    if set(frame.index) != required:
        raise ValueError(f"Umbrales incompletos en {path}: {sorted(frame.index)}")
    return {
        algorithm: {95: float(frame.loc[algorithm, "tau_95"]), 99: float(frame.loc[algorithm, "tau_99"])}
        for algorithm in required
    }


def choose_offset(record, placement, size, rng):
    total = int(record["size"])
    if placement in {"zero", "code_cave"}:
        prefix = "zero" if placement == "zero" else "cave"
        runs = [
            (int(start), int(length))
            for start, length in zip(record[f"{prefix}_starts"], record[f"{prefix}_lengths"])
            if length >= size
        ]
        start, length = runs[int(rng.integers(len(runs)))]
        return start + int(rng.integers(length - size + 1))
    if placement == "uniform":
        return int(rng.integers(total - size + 1))
    quarter = int(placement[1]) - 1
    return min(quarter * total // 4, total - size)


def replacement(content, size, rng):
    if content == "zero":
        return bytes(size)
    if content == "nop":
        return b"\x90" * size
    if content == "int3":
        return b"\xCC" * size
    if content == "random":
        return rng.bytes(size)
    if content == "shellcode":
        return (SHELLCODE * math.ceil(size / len(SHELLCODE)))[:size]
    raise ValueError(content)


def eligible_pool(pool, placement, size):
    eligible = pool[pool["size"] >= size]
    if placement in {"zero", "code_cave"}:
        prefix = "zero" if placement == "zero" else "cave"
        eligible = eligible[
            eligible[f"{prefix}_lengths"].map(lambda lengths: len(lengths) > 0 and max(lengths) >= size)
        ]
    return eligible


def load_data(record, mode, root):
    if mode == "pages":
        return bytes(record["data"])
    with open(os.path.join(root, record["path"]), "rb") as handle:
        return handle.read()


def threshold_pass(algorithm, value, thresholds, acceptance):
    if value is None or pd.isna(value):
        return None
    threshold = thresholds[algorithm][acceptance]
    return bool(value >= threshold) if algorithm != "tlsh" else bool(value <= threshold)


def run_cell(pool, mode, root, out, placement, content, size, repetitions, workers, seed, thresholds):
    shard = os.path.join(out, "trials", f"{placement}__{content}__{size:06d}.parquet")
    if os.path.exists(shard):
        return "existing", 0
    eligible = eligible_pool(pool, placement, size)
    if eligible.empty:
        marker = {column: None for column in TRIAL_COLUMNS}
        marker.update({
            "attempted": False, "placement": placement, "content": content, "write_size": size,
            "eligible_artifacts": 0, "changed": False,
        })
        pq.write_table(pa.Table.from_pylist([marker]), shard, compression="zstd")
        return "empty", 0

    rng = stable_rng(seed, placement, content, size)
    picks = rng.choice(len(eligible), min(repetitions, len(eligible)), replace=False)
    rows, changed_paths = [], []
    tmp_root = os.path.join(out, "tmp")
    os.makedirs(tmp_root, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tmp_root) as temporary:
        for attempt, position in enumerate(picks):
            record = eligible.iloc[int(position)]
            data = load_data(record, mode, root)
            offset = choose_offset(record, placement, size, rng)
            value = replacement(content, size, rng)
            original_slice = np.frombuffer(data, dtype=np.uint8, count=size, offset=offset)
            changed_bytes = int(np.count_nonzero(original_slice != np.frombuffer(value, dtype=np.uint8)))
            row = {
                "attempted": True,
                "attempt": attempt,
                "artifact_id": record.artifact_id,
                "stratum": record.stratum,
                "architecture": record.architecture,
                "system": record.system,
                "kind": record.kind,
                "original_size": int(record["size"]),
                "placement": placement,
                "content": content,
                "write_size": size,
                "offset": offset,
                "eligible_artifacts": len(eligible),
                "changed": changed_bytes > 0,
                "changed_bytes": changed_bytes,
                "original_sdhash_features": int(record.sdhash_features),
                "original_tlsh": record.tlsh,
                "original_ssdeep": record.ssdeep,
                "original_sdhash": record.sdhash,
            }
            if changed_bytes:
                mutant = bytearray(data)
                mutant[offset:offset + size] = value
                mutant = bytes(mutant)
                path = os.path.join(temporary, f"{attempt:06d}")
                with open(path, "wb") as handle:
                    handle.write(mutant)
                changed_paths.append((len(rows), path))
                row["mutant_tlsh"] = tlsh_digest(mutant)
                row["mutant_ssdeep"] = ssdeep.hash(mutant)
            rows.append(row)

        mutant_sdhash = sdhash_files(
            [path for _, path in changed_paths], workers, include_scheme=(mode == "pe")
        )
        sdhash_by_row = {row_number: digest for (row_number, _), digest in zip(changed_paths, mutant_sdhash)}
        score_lines, score_rows = [], []
        for row_number, digest in sdhash_by_row.items():
            row = rows[row_number]
            mutant_features = sdhash_features(digest)
            row["mutant_sdhash"] = digest
            row["mutant_sdhash_features"] = mutant_features
            if row["original_sdhash_features"] >= MIN_SDHASH_FEATURES and mutant_features >= MIN_SDHASH_FEATURES:
                score_rows.append(row_number)
                score_lines.append(f"{full_sdbf(row['original_sdhash'])}\t{full_sdbf(digest)}")
        for row_number, score in zip(score_rows, sdhash_scores(score_lines, workers)):
            rows[row_number]["sdhash_score"] = score

    for row in rows:
        if not row["changed"]:
            continue
        row["ssdeep_score"] = ssdeep.compare(row["original_ssdeep"], row["mutant_ssdeep"])
        row["tlsh_dist"] = tlsh_distance(row["original_tlsh"], row["mutant_tlsh"])
        for algorithm, score_column, digest_column in (
            ("ssdeep", "ssdeep_score", "ssdeep"),
            ("tlsh", "tlsh_dist", "tlsh"),
            ("sdhash", "sdhash_score", "sdhash"),
        ):
            value = row.get(score_column)
            comparable = value is not None and not pd.isna(value)
            row[f"{algorithm}_exact"] = (
                row.get(f"original_{digest_column}") == row.get(f"mutant_{digest_column}") if comparable else None
            )
            row[f"{algorithm}_saturated"] = (
                value == (0 if algorithm == "tlsh" else 100) if comparable else None
            )
            row[f"{algorithm}_tau95"] = threshold_pass(algorithm, value, thresholds, 95)
            row[f"{algorithm}_tau99"] = threshold_pass(algorithm, value, thresholds, 99)

    output_rows = [{column: row.get(column) for column in TRIAL_COLUMNS} for row in rows]
    temporary_shard = shard + ".part"
    pq.write_table(pa.Table.from_pylist(output_rows), temporary_shard, compression="zstd")
    os.replace(temporary_shard, shard)
    return "done", sum(row["changed"] for row in rows)


def wilson(successes, count, z=1.959963984540054):
    if count == 0:
        return math.nan, math.nan, math.nan
    proportion = successes / count
    denominator = 1 + z * z / count
    center = (proportion + z * z / (2 * count)) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) / count + z * z / (4 * count * count)) / denominator
    return 100 * proportion, max(0.0, 100 * (center - margin)), min(100.0, 100 * (center + margin))


def summarize(out):
    files = sorted(glob.glob(os.path.join(out, "trials", "*.parquet")))
    trials = pa.concat_tables(
        [pq.read_table(path) for path in files], promote_options="permissive"
    ).to_pandas()
    attempted = trials[trials.attempted == True]  # noqa: E712
    cells = attempted.groupby(["placement", "content", "write_size"], dropna=False).agg(
        attempts=("attempted", "size"),
        changed=("changed", "sum"),
        eligible_artifacts=("eligible_artifacts", "max"),
    ).reset_index()
    cells["no_op"] = cells.attempts - cells.changed
    cells.to_csv(os.path.join(out, "attempts.csv"), index=False)

    rows = []
    changed = attempted[attempted.changed == True]  # noqa: E712
    for keys, group in changed.groupby(["placement", "content", "write_size"]):
        for algorithm, score_column in (("ssdeep", "ssdeep_score"), ("tlsh", "tlsh_dist"), ("sdhash", "sdhash_score")):
            comparable = group[group[score_column].notna()]
            row = {
                "placement": keys[0], "content": keys[1], "write_size": keys[2], "algorithm": algorithm,
                "changed": len(group), "comparable": len(comparable),
                "comparable_%": 100 * len(comparable) / len(group),
                "median_score": comparable[score_column].median() if len(comparable) else math.nan,
            }
            for metric in ("exact", "saturated", "tau95", "tau99"):
                values = comparable[f"{algorithm}_{metric}"].dropna().astype(bool)
                rate, low, high = wilson(int(values.sum()), len(values))
                row[f"{metric}_%"] = rate
                row[f"{metric}_ci_low"] = low
                row[f"{metric}_ci_high"] = high
            rows.append(row)
    summary = pd.DataFrame(rows)
    summary.to_csv(os.path.join(out, "summary.csv"), index=False)
    return cells, summary


def parse_list(value, cast=str):
    return [cast(item) for item in value.split(",") if item]


def config_for(args):
    return {
        "mode": args.mode,
        "root": os.path.abspath(args.root),
        "index": os.path.abspath(args.index),
        "thresholds": os.path.abspath(args.thresholds),
        "preprocess": getattr(args, "preprocess", None),
        "pool_per_stratum": args.pool_per_stratum,
        "repetitions": args.repetitions,
        "sizes": args.sizes,
        "placements": args.placements,
        "contents": args.contents,
        "seed": args.seed,
    }


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("pages", "pe"):
        sub = subparsers.add_parser(mode)
        sub.add_argument("root", help="Corpus ZIP para pages; raíz PE para pe")
        sub.add_argument("index", help="Índice E0 SUM para pages; índice PE para pe")
        sub.add_argument("thresholds")
        sub.add_argument("out")
        sub.add_argument("--workers", type=int, default=max(1, os.cpu_count() // 2))
        sub.add_argument("--repetitions", type=int, default=200)
        sub.add_argument("--pool-per-stratum", type=int, default=250 if mode == "pages" else 100)
        sub.add_argument("--sizes", type=lambda value: parse_list(value, int), default=(
            [1, 4, 16, 64, 256, 512, 1024, 2048] if mode == "pages"
            else [16, 64, 256, 1024, 4096, 16384, 65536]
        ))
        sub.add_argument("--placements", type=lambda value: parse_list(value), default=list(PLACEMENTS))
        sub.add_argument("--contents", type=lambda value: parse_list(value), default=list(CONTENTS))
        sub.add_argument("--seed", type=int, default=20261028)
        if mode == "pages":
            sub.add_argument("--preprocess", default="sum-best")
    args = parser.parse_args()
    unknown_placements = set(args.placements) - set(PLACEMENTS)
    unknown_contents = set(args.contents) - set(CONTENTS)
    if unknown_placements or unknown_contents:
        parser.error(f"Valores desconocidos: placements={unknown_placements}, contents={unknown_contents}")

    os.makedirs(os.path.join(args.out, "trials"), exist_ok=True)
    config = config_for(args)
    config_path = os.path.join(args.out, "config.json")
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as handle:
            previous = json.load(handle)
        if previous != config:
            raise SystemExit(f"La configuración no coincide con {config_path}; use otro directorio de salida")
    else:
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, sort_keys=True)
            handle.write("\n")

    pool_path = os.path.join(args.out, "pool.parquet")
    if os.path.exists(pool_path):
        pool = pq.read_table(pool_path).to_pandas()
    else:
        if args.mode == "pages":
            pool = page_pool(args.root, args.index, args.preprocess, args.pool_per_stratum, args.seed)
        else:
            pool = pe_pool(args.root, args.index, args.pool_per_stratum, args.seed)
        pq.write_table(pa.Table.from_pandas(pool, preserve_index=False), pool_path, compression="zstd")
    print(f"pool: {len(pool)} artefactos, {pool.stratum.nunique()} estratos", flush=True)

    thresholds = load_thresholds(args.thresholds)
    total = len(args.placements) * len(args.contents) * len(args.sizes)
    completed = 0
    for placement in args.placements:
        for content in args.contents:
            for size in args.sizes:
                status, changed = run_cell(
                    pool, args.mode, args.root, args.out, placement, content, size, args.repetitions,
                    args.workers, args.seed, thresholds,
                )
                completed += 1
                print(
                    f"{completed}/{total} {placement}/{content}/{size}: {status}, {changed} cambios válidos",
                    flush=True,
                )
    cells, summary = summarize(args.out)
    print(
        f"Hecho: {int(cells.attempts.sum())} intentos, {int(cells.changed.sum())} cambios válidos, "
        f"{len(summary)} filas de resumen",
        flush=True,
    )


if __name__ == "__main__":
    main()
