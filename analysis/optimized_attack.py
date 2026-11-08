"""E4: oracle optimization of payload placement and surrounding free bytes.

The experiment starts from the stratified E3 page pool (or, with --mode pe, the E8 pool of
complete PE files). For every distinct eligible artefact it keeps the payload fixed, evaluates
several positions inside a null run, then evaluates optional padding before or after the payload.
Padding is attacker-controlled space in the same run. The baseline, placement-only oracle and
joint placement+padding oracle are reported separately for each digest.

This is an upper-bound attack: the attacker knows the reference digest and the scoring algorithm.
No artifact is sampled twice within a cell. Candidates are written to OUT/tmp as they are built,
so large PE files are never held in memory more than once.

Usage:
  python optimized_attack.py E3_POOL E1_THRESHOLDS OUT [options]
  python optimized_attack.py E8_POOL E8_THRESHOLDS OUT --mode pe --root PE_ROOT [options]
"""
import argparse
import glob
import json
import math
import os
import tempfile

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep

from preservation_margin import SHELLCODE, load_data, load_thresholds, stable_rng, wilson
from sda_common import (
    MIN_SDHASH_FEATURES,
    full_sdbf,
    sdhash_features,
    sdhash_files,
    sdhash_scores,
    tlsh_digest,
    tlsh_distance,
)

SCOPES = ("zero", "code_cave")
PADDING_PATTERNS = ("none", "pre_nop", "post_nop", "pre_int3", "post_int3",
                    "pre_random", "post_random", "pre_counter", "post_counter")
ALGORITHMS = ("ssdeep", "tlsh", "sdhash")


def payload(size):
    return (SHELLCODE * math.ceil(size / len(SHELLCODE)))[:size]


def repeated(pattern, size):
    return (pattern * math.ceil(size / len(pattern)))[:size]


def padding_bytes(name, size, rng):
    pattern = name.split("_", 1)[1]
    if pattern == "nop":
        return b"\x90" * size
    if pattern == "int3":
        return b"\xCC" * size
    if pattern == "random":
        return rng.bytes(size)
    if pattern == "counter":
        return repeated(bytes(range(256)), size)
    raise ValueError(name)


def candidate_starts(starts, lengths, required, count, rng):
    positions = []
    for start, length in zip(starts, lengths):
        if length >= required:
            positions.extend(range(int(start), int(start) + int(length) - required + 1))
    if not positions:
        return []
    chosen = rng.choice(len(positions), min(count, len(positions)), replace=False)
    return [positions[int(index)] for index in chosen]


def eligible(pool, scope, payload_size, padding_size):
    prefix = "zero" if scope == "zero" else "cave"
    required = payload_size + padding_size
    return pool[
        pool[f"{prefix}_lengths"].map(
            lambda lengths: len(lengths) > 0 and max(lengths) >= required
        )
    ]


def make_candidate(data, region_start, payload_value, padding_size, variant, rng):
    mutant = bytearray(data)
    if variant == "none":
        payload_offset = region_start
    elif variant.startswith("pre_"):
        padding = padding_bytes(variant, padding_size, rng)
        mutant[region_start:region_start + padding_size] = padding
        payload_offset = region_start + padding_size
    else:
        payload_offset = region_start
        padding = padding_bytes(variant, padding_size, rng)
        padding_start = payload_offset + len(payload_value)
        mutant[padding_start:padding_start + padding_size] = padding
    mutant[payload_offset:payload_offset + len(payload_value)] = payload_value
    mutant = bytes(mutant)
    changed = int(np.count_nonzero(np.frombuffer(data, dtype=np.uint8) != np.frombuffer(mutant, dtype=np.uint8)))
    return mutant, payload_offset, changed


def threshold_pass(algorithm, score, thresholds, acceptance):
    if score is None or pd.isna(score):
        return None
    threshold = thresholds[algorithm][acceptance]
    return bool(score <= threshold) if algorithm == "tlsh" else bool(score >= threshold)


def score_candidates(candidates, original, workers, include_scheme):
    """Score candidates whose ssdeep/TLSH digests are computed and whose bytes are in 'path'."""
    for candidate in candidates:
        candidate["ssdeep_score"] = ssdeep.compare(original.ssdeep, candidate["mutant_ssdeep"])
        candidate["tlsh_score"] = tlsh_distance(original.tlsh, candidate["mutant_tlsh"])
    digests = sdhash_files([candidate["path"] for candidate in candidates], workers, include_scheme)
    comparable_rows, lines = [], []
    for number, (candidate, digest) in enumerate(zip(candidates, digests)):
        features = sdhash_features(digest)
        candidate["mutant_sdhash"] = digest
        candidate["mutant_sdhash_features"] = features
        candidate["sdhash_score"] = None
        if original.sdhash_features >= MIN_SDHASH_FEATURES and features >= MIN_SDHASH_FEATURES:
            comparable_rows.append(number)
            lines.append(f"{full_sdbf(original.sdhash)}\t{full_sdbf(digest)}")
    for number, score in zip(comparable_rows, sdhash_scores(lines, workers)):
        candidates[number]["sdhash_score"] = score


def score_key(candidate, algorithm):
    score = candidate[f"{algorithm}_score"]
    if score is None or pd.isna(score):
        return None
    objective = -score if algorithm == "tlsh" else score
    padding_penalty = candidate["changed_bytes"]
    none_preference = candidate["padding"] == "none"
    return objective, -padding_penalty, none_preference


def best_candidate(candidates, algorithm):
    comparable = [(score_key(candidate, algorithm), candidate) for candidate in candidates]
    comparable = [item for item in comparable if item[0] is not None]
    return max(comparable, key=lambda item: item[0])[1] if comparable else None


def stage_values(candidate, algorithm, original, thresholds):
    if candidate is None:
        return {
            "score": None, "comparable": False, "exact": None, "saturated": None,
            "tau95": None, "tau99": None, "offset": None, "padding": None, "changed_bytes": None,
        }
    score = candidate[f"{algorithm}_score"]
    comparable = score is not None and not pd.isna(score)
    if algorithm == "ssdeep":
        exact = original.ssdeep == candidate["mutant_ssdeep"] if comparable else None
    elif algorithm == "tlsh":
        exact = original.tlsh == candidate["mutant_tlsh"] if comparable else None
    else:
        exact = original.sdhash == candidate["mutant_sdhash"] if comparable else None
    return {
        "score": score,
        "comparable": comparable,
        "exact": exact,
        "saturated": score == (0 if algorithm == "tlsh" else 100) if comparable else None,
        "tau95": threshold_pass(algorithm, score, thresholds, 95),
        "tau99": threshold_pass(algorithm, score, thresholds, 99),
        "offset": candidate["payload_offset"],
        "padding": candidate["padding"],
        "changed_bytes": candidate["changed_bytes"],
    }


def improvement(baseline, optimized, algorithm):
    if baseline is None or optimized is None or pd.isna(baseline) or pd.isna(optimized):
        return None
    return baseline - optimized if algorithm == "tlsh" else optimized - baseline


def optimize_artifact(record, data, scope, payload_size, padding_size, offsets, workers, seed, thresholds,
                      include_scheme, tmp_root):
    prefix = "zero" if scope == "zero" else "cave"
    rng = stable_rng(seed, record.artifact_id, scope, payload_size)
    starts = candidate_starts(
        getattr(record, f"{prefix}_starts"), getattr(record, f"{prefix}_lengths"),
        payload_size + padding_size, offsets, rng,
    )
    payload_value = payload(payload_size)
    candidates = []
    with tempfile.TemporaryDirectory(dir=tmp_root) as temporary:
        for offset_rank, region_start in enumerate(starts):
            for variant in PADDING_PATTERNS:
                candidate_rng = stable_rng(seed, record.artifact_id, scope, payload_size, region_start, variant)
                mutant, payload_offset, changed = make_candidate(
                    data, region_start, payload_value, padding_size, variant, candidate_rng,
                )
                path = os.path.join(temporary, f"{len(candidates):06d}")
                with open(path, "wb") as handle:
                    handle.write(mutant)
                candidates.append({
                    "offset_rank": offset_rank,
                    "region_start": region_start,
                    "payload_offset": payload_offset,
                    "padding": variant,
                    "changed_bytes": changed,
                    "path": path,
                    "mutant_ssdeep": ssdeep.hash(mutant),
                    "mutant_tlsh": tlsh_digest(mutant),
                })
        score_candidates(candidates, record, workers, include_scheme)
    baseline = next(candidate for candidate in candidates if candidate["offset_rank"] == 0 and candidate["padding"] == "none")
    placement_candidates = [candidate for candidate in candidates if candidate["padding"] == "none"]
    rows = []
    for algorithm in ALGORITHMS:
        placement = best_candidate(placement_candidates, algorithm)
        optimized = best_candidate(candidates, algorithm)
        stages = {
            "baseline": stage_values(baseline, algorithm, record, thresholds),
            "placement": stage_values(placement, algorithm, record, thresholds),
            "optimized": stage_values(optimized, algorithm, record, thresholds),
        }
        row = {
            "scope": scope,
            "payload_size": payload_size,
            "padding_size": padding_size,
            "artifact_id": record.artifact_id,
            "stratum": record.stratum,
            "architecture": record.architecture,
            "system": record.system,
            "algorithm": algorithm,
            "candidate_offsets": len(starts),
            "candidates": len(candidates),
        }
        for stage, values in stages.items():
            row.update({f"{stage}_{key}": value for key, value in values.items()})
        row["placement_gain"] = improvement(stages["baseline"]["score"], stages["placement"]["score"], algorithm)
        row["optimized_gain"] = improvement(stages["baseline"]["score"], stages["optimized"]["score"], algorithm)
        row["placement_new_tau95"] = bool(stages["placement"]["tau95"]) and not bool(stages["baseline"]["tau95"])
        row["optimized_new_tau95"] = bool(stages["optimized"]["tau95"]) and not bool(stages["baseline"]["tau95"])
        row["optimized_new_tau99"] = bool(stages["optimized"]["tau99"]) and not bool(stages["baseline"]["tau99"])
        rows.append(row)
    return rows


def run_cell(pool, out, scope, payload_size, max_padding, offsets, artifacts, workers, seed, thresholds,
             mode, root):
    padding_size = min(payload_size, max_padding)
    shard = os.path.join(out, "trials", f"{scope}__{payload_size:06d}.parquet")
    empty_marker = shard + ".empty"
    if os.path.exists(shard) or os.path.exists(empty_marker):
        return "existing", 0
    candidates = eligible(pool, scope, payload_size, padding_size)
    if candidates.empty:
        with open(empty_marker, "w", encoding="utf-8") as handle:
            handle.write("no eligible artifacts\n")
        return "empty", 0
    rng = stable_rng(seed, "artifacts", scope, payload_size)
    positions = rng.choice(len(candidates), min(artifacts, len(candidates)), replace=False)
    selected = candidates.iloc[np.sort(positions)]
    tmp_root = os.path.join(out, "tmp")
    os.makedirs(tmp_root, exist_ok=True)
    rows = []
    for number, record in enumerate(selected.itertuples(index=False), 1):
        rows.extend(optimize_artifact(
            record, load_data(record._asdict(), mode, root), scope, payload_size, padding_size, offsets,
            workers, seed, thresholds, include_scheme=(mode == "pe"), tmp_root=tmp_root,
        ))
        if number % 20 == 0 or number == len(selected):
            print(f"  {number}/{len(selected)} artefactos", flush=True)
    temporary = shard + ".part"
    pq.write_table(pa.Table.from_pylist(rows), temporary, compression="zstd")
    os.replace(temporary, shard)
    return "done", len(selected)


def summarize(out):
    files = sorted(glob.glob(os.path.join(out, "trials", "*.parquet")))
    trials = pa.concat_tables([pq.read_table(path) for path in files], promote_options="permissive").to_pandas()
    rows = []
    for keys, group in trials.groupby(["scope", "payload_size", "padding_size", "algorithm"]):
        row = {
            "scope": keys[0], "payload_size": keys[1], "padding_size": keys[2],
            "algorithm": keys[3], "artifacts": len(group),
        }
        for stage in ("baseline", "placement", "optimized"):
            comparable = group[f"{stage}_comparable"].eq(True)
            count = int(comparable.sum())
            row[f"{stage}_comparable"] = count
            row[f"{stage}_median_score"] = group.loc[comparable, f"{stage}_score"].median() if count else math.nan
            for metric in ("exact", "saturated"):
                values = group.loc[comparable, f"{stage}_{metric}"].eq(True)
                row[f"{stage}_{metric}_%"] = 100 * values.mean() if count else math.nan
            for acceptance in (95, 99):
                passed = group[f"{stage}_tau{acceptance}"].eq(True)
                rate, low, high = wilson(int(passed.sum()), len(group))
                row[f"{stage}_tau{acceptance}_all_%"] = rate
                row[f"{stage}_tau{acceptance}_ci_low"] = low
                row[f"{stage}_tau{acceptance}_ci_high"] = high
                row[f"{stage}_tau{acceptance}_comparable_%"] = (
                    100 * passed[comparable].mean() if count else math.nan
                )
        for stage in ("placement", "optimized"):
            row[f"{stage}_median_gain"] = group[f"{stage}_gain"].median()
            row[f"{stage}_new_tau95"] = int(group[f"{stage}_new_tau95"].sum())
        row["optimized_new_tau99"] = int(group.optimized_new_tau99.sum())
        rows.append(row)
    summary = pd.DataFrame(rows)
    summary.to_csv(os.path.join(out, "summary.csv"), index=False)
    padding = trials.groupby(["scope", "payload_size", "algorithm", "optimized_padding"]).size().rename("artifacts").reset_index()
    padding.to_csv(os.path.join(out, "padding_choices.csv"), index=False)
    return trials, summary


def parse_csv(value, cast=str):
    return [cast(item) for item in value.split(",") if item]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pool")
    parser.add_argument("thresholds")
    parser.add_argument("out")
    parser.add_argument("--sizes", type=lambda value: parse_csv(value, int), default=[16, 64, 256, 512])
    parser.add_argument("--scopes", type=lambda value: parse_csv(value), default=list(SCOPES))
    parser.add_argument("--artifacts", type=int, default=200)
    parser.add_argument("--offsets", type=int, default=16)
    parser.add_argument("--max-padding", type=int, default=256)
    parser.add_argument("--workers", type=int, default=max(1, os.cpu_count() // 2))
    parser.add_argument("--seed", type=int, default=20261028)
    parser.add_argument("--mode", choices=("pages", "pe"), default="pages")
    parser.add_argument("--root", help="raíz de los PE (solo --mode pe)")
    args = parser.parse_args()
    unknown = set(args.scopes) - set(SCOPES)
    if unknown:
        parser.error(f"Scopes desconocidos: {sorted(unknown)}")
    if (args.mode == "pe") != (args.root is not None):
        parser.error("--root es obligatorio con --mode pe y no se admite con --mode pages")
    os.makedirs(os.path.join(args.out, "trials"), exist_ok=True)
    config = {
        "pool": os.path.abspath(args.pool),
        "thresholds": os.path.abspath(args.thresholds),
        "sizes": args.sizes,
        "scopes": args.scopes,
        "artifacts": args.artifacts,
        "offsets": args.offsets,
        "max_padding": args.max_padding,
        "seed": args.seed,
    }
    if args.mode == "pe":  # E4 (pages) keeps its original config.json
        config.update(mode="pe", root=os.path.abspath(args.root))
    config_path = os.path.join(args.out, "config.json")
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as handle:
            if json.load(handle) != config:
                raise SystemExit(f"La configuración no coincide con {config_path}; use otro directorio")
    else:
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, sort_keys=True)
            handle.write("\n")
    pool = pq.read_table(args.pool).to_pandas()
    thresholds = load_thresholds(args.thresholds)
    total = len(args.scopes) * len(args.sizes)
    completed = 0
    for scope in args.scopes:
        for size in args.sizes:
            status, count = run_cell(
                pool, args.out, scope, size, args.max_padding, args.offsets, args.artifacts,
                args.workers, args.seed, thresholds, args.mode, args.root,
            )
            completed += 1
            print(f"{completed}/{total} {scope}/{size}: {status}, {count} artefactos", flush=True)
    trials, summary = summarize(args.out)
    print(f"Hecho: {len(trials) // len(ALGORITHMS)} artefactos-celda, {len(trials)} resultados por algoritmo")
    print(summary[["scope", "payload_size", "algorithm", "artifacts", "baseline_tau95_all_%",
                   "placement_tau95_all_%", "optimized_tau95_all_%", "optimized_new_tau95"]].to_string(index=False))


if __name__ == "__main__":
    main()
