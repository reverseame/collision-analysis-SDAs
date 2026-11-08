"""E8 baseline: legitimate full-PE drift between Windows releases.

Files are matched by architecture, type and case-insensitive basename. Ambiguous duplicate names
inside one VM are excluded instead of choosing an arbitrary path. Comparisons follow two product
families: Server 2012 R2 -> 2016 -> 2019 and Windows 7 -> Windows 10 21H2.

Outputs: OUT/e8_legitimate_pairs.parquet and OUT/e8_thresholds.csv.
Usage: python pe_drift_baseline.py PE_INDEX OUT [WORKERS]
"""
import glob
import os
import sys

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from sda_common import MIN_SDHASH_FEATURES, full_sdbf, sdhash_scores, ssdeep_score, tlsh_distance

TRANSITIONS = (
    (101, 103, "server_2012r2_2016"),
    (103, 104, "server_2016_2019"),
    (102, 107, "desktop_7_10"),
)
KEY = ["architecture", "kind", "name"]
SIDE = KEY + ["path", "sha256", "tlsh", "ssdeep", "sdhash", "sdhash_features", "size"]


def load_index(index_dir):
    files = sorted(glob.glob(os.path.join(index_dir, "shards", "*.parquet")))
    if not files:
        raise SystemExit(f"No hay shards en {index_dir}/shards")
    return pa.concat_tables([pq.read_table(path) for path in files]).to_pandas()


def matched_pairs(index):
    counts = index.groupby(["machine"] + KEY).size()
    ambiguous = counts[counts > 1]
    if len(ambiguous):
        bad = pd.MultiIndex.from_frame(index[["machine"] + KEY]).isin(ambiguous.index)
        print(f"PE excluidos por nombre ambiguo dentro de una VM: {int(bad.sum())}", flush=True)
        index = index[~bad]
    parts = []
    for left_machine, right_machine, transition in TRANSITIONS:
        left = index[index.machine == left_machine][SIDE]
        right = index[index.machine == right_machine][SIDE]
        pairs = left.merge(right, on=KEY, suffixes=("_a", "_b"))
        pairs.insert(0, "transition", transition)
        print(f"{transition}: {len(pairs)} pares", flush=True)
        parts.append(pairs)
    return pd.concat(parts, ignore_index=True)


def main():
    index_dir, out = sys.argv[1], sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    os.makedirs(out, exist_ok=True)
    pairs = matched_pairs(load_index(index_dir))
    pairs["identical"] = pairs.sha256_a == pairs.sha256_b
    pairs["ssdeep_score"] = [ssdeep_score(a, b) for a, b in zip(pairs.ssdeep_a, pairs.ssdeep_b)]
    pairs["tlsh_dist"] = [tlsh_distance(a, b) for a, b in zip(pairs.tlsh_a, pairs.tlsh_b)]
    comparable = (pairs.sdhash_features_a >= MIN_SDHASH_FEATURES) & (
        pairs.sdhash_features_b >= MIN_SDHASH_FEATURES
    )
    pairs["sdhash_score"] = np.nan
    lines = [
        f"{full_sdbf(a)}\t{full_sdbf(b)}"
        for a, b in zip(pairs.loc[comparable, "sdhash_a"], pairs.loc[comparable, "sdhash_b"])
    ]
    pairs.loc[comparable, "sdhash_score"] = sdhash_scores(lines, workers)

    keep = KEY + [
        "transition", "path_a", "path_b", "size_a", "size_b", "identical",
        "ssdeep_score", "tlsh_dist", "sdhash_score",
    ]
    pq.write_table(
        pa.Table.from_pandas(pairs[keep], preserve_index=False),
        os.path.join(out, "e8_legitimate_pairs.parquet"),
        compression="zstd",
    )

    rows = []
    for subset, mask in (("todos", np.ones(len(pairs), dtype=bool)), ("no_identicos", ~pairs.identical.to_numpy())):
        for algorithm, column, higher_better in (
            ("ssdeep", "ssdeep_score", True),
            ("tlsh", "tlsh_dist", False),
            ("sdhash", "sdhash_score", True),
        ):
            values = pairs.loc[mask, column].dropna().to_numpy()
            row = {
                "pares": subset,
                "algoritmo": algorithm,
                "n": len(values),
                "comparables_%": 100 * len(values) / mask.sum(),
                "mediana": np.median(values),
            }
            for acceptance in (90, 95, 99):
                percentile = 100 - acceptance if higher_better else acceptance
                row[f"tau_{acceptance}"] = np.percentile(values, percentile)
            rows.append(row)
    thresholds = pd.DataFrame(rows)
    thresholds.to_csv(os.path.join(out, "e8_thresholds.csv"), index=False)
    print(
        f"pares: {len(pairs)} | idénticos: {int(pairs.identical.sum())} "
        f"({100 * pairs.identical.mean():.1f} %)",
        flush=True,
    )
    print(thresholds.to_string(index=False, float_format=lambda value: f"{value:.1f}"))


if __name__ == "__main__":
    main()
