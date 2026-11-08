"""E5: explain E4 with internal digest-state changes.

The script reconstructs every baseline, placement and optimized E4 winner and validates its stored
score. It then records:

* ssdeep 2.14.1 rolling-hash cut points at the digest block sizes;
* TLSH checksum, length value, quartile ratios and 128 encoded bucket quartiles;
* sdhash feature counts and changed bits in its serialized Bloom filters.

The ssdeep rolling state follows release-2.14.1/fuzzy.c. TLSH parsing follows the 128-bucket,
one-byte-checksum layout used by py-tlsh 4.7.2. sdhash metrics operate on the v3.4 SDBF itself;
they expose selected-feature aggregates, not the original feature byte offsets.

Usage: python mechanism_analysis.py E3_POOL E4_DIR OUT [WORKERS]
"""
import base64
import difflib
import glob
import math
import os
import sys
import tempfile

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep

from optimized_attack import make_candidate, payload
from preservation_margin import stable_rng
from sda_common import (
    MIN_SDHASH_FEATURES,
    full_sdbf,
    sdhash_features,
    sdhash_files,
    sdhash_scores,
    tlsh_digest,
    tlsh_distance,
)

STAGES = ("baseline", "placement", "optimized")
UINT32 = 0xFFFFFFFF
ROLLING_WINDOW = 7


def ssdeep_cutpoints(data, block_size):
    """Piece boundaries from ssdeep 2.14.1's seven-byte rolling hash."""
    window = [0] * ROLLING_WINDOW
    h1 = h2 = h3 = index = 0
    cuts = []
    for offset, value in enumerate(data):
        h2 = (h2 - h1 + ROLLING_WINDOW * value) & UINT32
        h1 = (h1 + value - window[index]) & UINT32
        window[index] = value
        index = (index + 1) % ROLLING_WINDOW
        h3 = ((h3 << 5) ^ value) & UINT32
        horg = ((h1 + h2 + h3) + 1) & UINT32
        if horg and horg % block_size == 0:
            cuts.append(offset)
    return cuts


def set_metrics(original, mutant, prefix):
    left, right = set(original), set(mutant)
    shared = len(left & right)
    union = len(left | right)
    return {
        f"{prefix}_original": len(left),
        f"{prefix}_mutant": len(right),
        f"{prefix}_shared": shared,
        f"{prefix}_created": len(right - left),
        f"{prefix}_removed": len(left - right),
        f"{prefix}_jaccard": shared / union if union else 1.0,
    }


def ssdeep_metrics(original_data, mutant_data, original_digest, mutant_digest):
    original_parts = original_digest.split(":", 2)
    mutant_parts = mutant_digest.split(":", 2)
    block_size = int(original_parts[0])
    first_original = ssdeep_cutpoints(original_data, block_size)
    first_mutant = ssdeep_cutpoints(mutant_data, block_size)
    second_original = ssdeep_cutpoints(original_data, block_size * 2)
    second_mutant = ssdeep_cutpoints(mutant_data, block_size * 2)
    result = {
        "ssdeep_block_size": block_size,
        "ssdeep_block_size_changed": int(mutant_parts[0]) != block_size,
        "ssdeep_digest_ratio": difflib.SequenceMatcher(None, original_digest, mutant_digest).ratio(),
        "ssdeep_hash1_ratio": difflib.SequenceMatcher(None, original_parts[1], mutant_parts[1]).ratio(),
        "ssdeep_hash2_ratio": difflib.SequenceMatcher(None, original_parts[2], mutant_parts[2]).ratio(),
    }
    result.update(set_metrics(first_original, first_mutant, "ssdeep_cut1"))
    result.update(set_metrics(second_original, second_mutant, "ssdeep_cut2"))
    return result


def unswap_hex_byte(value):
    return int(value[1] + value[0], 16)


def tlsh_components(digest):
    if digest == "-" or len(digest) != 70:
        return None
    checksum = unswap_hex_byte(digest[0:2])
    lvalue = unswap_hex_byte(digest[2:4])
    quartiles = unswap_hex_byte(digest[4:6])
    q1, q2 = quartiles & 0x0F, quartiles >> 4
    bucket_codes = []
    for byte in bytes.fromhex(digest[6:]):
        bucket_codes.extend((byte >> shift) & 0x03 for shift in (0, 2, 4, 6))
    return checksum, lvalue, q1, q2, bucket_codes


def tlsh_metrics(original_digest, mutant_digest):
    original = tlsh_components(original_digest)
    mutant = tlsh_components(mutant_digest)
    if original is None or mutant is None:
        return {}
    bucket_delta = [abs(left - right) for left, right in zip(original[4], mutant[4])]
    return {
        "tlsh_checksum_changed": original[0] != mutant[0],
        "tlsh_lvalue_delta": abs(original[1] - mutant[1]),
        "tlsh_q1_delta": abs(original[2] - mutant[2]),
        "tlsh_q2_delta": abs(original[3] - mutant[3]),
        "tlsh_bucket_codes_changed": sum(delta != 0 for delta in bucket_delta),
        "tlsh_bucket_code_abs_delta": sum(bucket_delta),
        "tlsh_bucket_codes_equal_%": 100 * sum(delta == 0 for delta in bucket_delta) / len(bucket_delta),
    }


def sdhash_tail(digest):
    if digest.startswith(("sdbf:", "sdbf-dd:")):
        header = digest.split(":", 3)
        digest = header[3][int(header[2]) + 1:]
    return digest


def sdhash_filters(digest):
    fields = sdhash_tail(digest).split(":")
    return [base64.b64decode(value) for value in fields[8:] if value]


def bit_count(data):
    return sum(value.bit_count() for value in data)


def sdhash_metrics(original_digest, mutant_digest):
    original_filters = sdhash_filters(original_digest)
    mutant_filters = sdhash_filters(mutant_digest)
    width = max(
        max((len(value) for value in original_filters), default=0),
        max((len(value) for value in mutant_filters), default=0),
    )
    count = max(len(original_filters), len(mutant_filters))
    original_bits = mutant_bits = shared = union = added = removed = 0
    for index in range(count):
        left = original_filters[index] if index < len(original_filters) else bytes(width)
        right = mutant_filters[index] if index < len(mutant_filters) else bytes(width)
        left = left.ljust(width, b"\0")
        right = right.ljust(width, b"\0")
        original_bits += bit_count(left)
        mutant_bits += bit_count(right)
        shared += sum((a & b).bit_count() for a, b in zip(left, right))
        union += sum((a | b).bit_count() for a, b in zip(left, right))
        added += sum((b & ~a & 0xFF).bit_count() for a, b in zip(left, right))
        removed += sum((a & ~b & 0xFF).bit_count() for a, b in zip(left, right))
    original_features = sdhash_features(original_digest)
    mutant_features = sdhash_features(mutant_digest)
    return {
        "sdhash_filters_original": len(original_filters),
        "sdhash_filters_mutant": len(mutant_filters),
        "sdhash_features_original": original_features,
        "sdhash_features_mutant": mutant_features,
        "sdhash_features_delta": mutant_features - original_features,
        "sdhash_bloom_bits_original": original_bits,
        "sdhash_bloom_bits_mutant": mutant_bits,
        "sdhash_bloom_bits_shared": shared,
        "sdhash_bloom_bits_added": added,
        "sdhash_bloom_bits_removed": removed,
        "sdhash_bloom_jaccard": shared / union if union else 1.0,
    }


def load_trials(e4):
    files = sorted(glob.glob(os.path.join(e4, "trials", "*.parquet")))
    return pa.concat_tables([pq.read_table(path) for path in files], promote_options="permissive").to_pandas()


def candidate_key(row, stage):
    offset = row[f"{stage}_offset"]
    padding_name = row[f"{stage}_padding"]
    if pd.isna(offset) or pd.isna(padding_name):
        return None
    return (
        row["scope"],
        row["artifact_id"],
        int(row["payload_size"]),
        int(row["padding_size"]),
        int(offset),
        str(padding_name),
    )


def reconstruct(key, original, seed):
    scope, artifact_id, payload_size, padding_size, payload_offset, padding_name = key
    region_start = payload_offset - padding_size if padding_name.startswith("pre_") else payload_offset
    rng = stable_rng(seed, artifact_id, scope, payload_size, region_start, padding_name)
    mutant, actual_offset, changed = make_candidate(
        bytes(original.data), region_start, payload(payload_size), padding_size, padding_name, rng,
    )
    if actual_offset != payload_offset:
        raise RuntimeError(f"Offset reconstruido incorrecto para {artifact_id}")
    return {
        "data": mutant,
        "changed_bytes": changed,
        "ssdeep": ssdeep.hash(mutant),
        "tlsh": tlsh_digest(mutant),
    }


def hash_candidates(candidates, originals, workers):
    with tempfile.TemporaryDirectory() as temporary:
        paths, keys = [], []
        for number, (key, candidate) in enumerate(candidates.items()):
            path = os.path.join(temporary, f"{number:06d}")
            with open(path, "wb") as handle:
                handle.write(candidate["data"])
            paths.append(path)
            keys.append(key)
        digests = sdhash_files(paths, workers)
    for key, digest in zip(keys, digests):
        candidates[key]["sdhash"] = digest

    score_keys, lines = [], []
    for key, candidate in candidates.items():
        original = originals[key[1]]
        candidate["sdhash_score"] = None
        if original.sdhash_features >= MIN_SDHASH_FEATURES and sdhash_features(candidate["sdhash"]) >= MIN_SDHASH_FEATURES:
            score_keys.append(key)
            lines.append(f"{full_sdbf(original.sdhash)}\t{full_sdbf(candidate['sdhash'])}")
    for key, score in zip(score_keys, sdhash_scores(lines, workers)):
        candidates[key]["sdhash_score"] = score


def validate_score(row, stage, candidate, original):
    stored = row[f"{stage}_score"]
    if row["algorithm"] == "ssdeep":
        calculated = ssdeep.compare(original.ssdeep, candidate["ssdeep"])
    elif row["algorithm"] == "tlsh":
        calculated = tlsh_distance(original.tlsh, candidate["tlsh"])
    else:
        calculated = candidate["sdhash_score"]
    if pd.isna(stored) and calculated is None:
        return
    if calculated is None or pd.isna(stored) or float(stored) != float(calculated):
        raise RuntimeError(
            f"Puntuación no reproducible: {row['artifact_id']} {row['algorithm']} {stage}: "
            f"guardada={stored}, calculada={calculated}"
        )


def mechanism_rows(pool, trials, workers, seed):
    originals = {row.artifact_id: row for row in pool.itertuples(index=False)}
    candidates = {}
    for row in trials.itertuples(index=False):
        original = originals[row.artifact_id]
        for stage in STAGES:
            key = candidate_key(row._asdict(), stage)
            if key is not None and key not in candidates:
                candidates[key] = reconstruct(key, original, seed)
    print(f"mutantes distintos reconstruidos: {len(candidates)}", flush=True)
    hash_candidates(candidates, originals, workers)

    rows = []
    for trial in trials.itertuples(index=False):
        values = trial._asdict()
        original = originals[trial.artifact_id]
        for stage in STAGES:
            key = candidate_key(values, stage)
            if key is None:
                continue
            candidate = candidates[key]
            validate_score(values, stage, candidate, original)
            row = {
                "scope": trial.scope,
                "payload_size": int(trial.payload_size),
                "padding_size": int(trial.padding_size),
                "artifact_id": trial.artifact_id,
                "stratum": trial.stratum,
                "algorithm": trial.algorithm,
                "stage": stage,
                "score": values[f"{stage}_score"],
                "comparable": bool(values[f"{stage}_comparable"]),
                "success95": bool(values[f"{stage}_tau95"]) if not pd.isna(values[f"{stage}_tau95"]) else False,
                "success99": bool(values[f"{stage}_tau99"]) if not pd.isna(values[f"{stage}_tau99"]) else False,
                "padding": values[f"{stage}_padding"],
                "changed_bytes": candidate["changed_bytes"],
            }
            if trial.algorithm == "ssdeep":
                row.update(ssdeep_metrics(bytes(original.data), candidate["data"], original.ssdeep, candidate["ssdeep"]))
            elif trial.algorithm == "tlsh":
                row.update(tlsh_metrics(original.tlsh, candidate["tlsh"]))
            else:
                row.update(sdhash_metrics(original.sdhash, candidate["sdhash"]))
            rows.append(row)
    return pd.DataFrame(rows)


def summarize(rows):
    metric_columns = [
        column for column in rows.columns
        if column not in {
            "scope", "payload_size", "padding_size", "artifact_id", "stratum", "algorithm", "stage",
            "score", "comparable", "success95", "success99", "padding", "changed_bytes",
        }
    ]
    output = []
    for keys, group in rows.groupby(["scope", "payload_size", "algorithm", "stage", "success95"]):
        scores = group.score.dropna()
        row = {
            "scope": keys[0], "payload_size": keys[1], "algorithm": keys[2], "stage": keys[3],
            "success95": keys[4], "artifacts": len(group),
            "median_score": scores.median() if len(scores) else math.nan,
            "median_changed_bytes": group.changed_bytes.median(),
        }
        for column in metric_columns:
            values = group[column].dropna()
            if len(values):
                row[f"median_{column}"] = values.astype(float).median()
        output.append(row)
    return pd.DataFrame(output)


def main():
    pool_path, e4, out = sys.argv[1:4]
    workers = int(sys.argv[4]) if len(sys.argv) > 4 else max(1, os.cpu_count() // 2)
    seed = 20261028
    os.makedirs(out, exist_ok=True)
    pool = pq.read_table(pool_path).to_pandas()
    trials = load_trials(e4)
    rows = mechanism_rows(pool, trials, workers, seed)
    pq.write_table(pa.Table.from_pandas(rows, preserve_index=False), os.path.join(out, "mechanisms.parquet"), compression="zstd")
    summary = summarize(rows)
    summary.to_csv(os.path.join(out, "mechanism_summary.csv"), index=False)
    print(f"filas instrumentadas: {len(rows)} | artefactos: {rows.artifact_id.nunique()}")
    print(summary[["scope", "payload_size", "algorithm", "stage", "success95", "artifacts", "median_score"]].to_string(index=False))


if __name__ == "__main__":
    main()
