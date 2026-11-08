"""E8b checks: exact-digest counts per stage, reconstruction of every exact TLSH winner, and the
TLSH mechanism (baseline mutants at distance 1 that differ only in the checksum byte).

Usage: python pe_optimized_check.py E8_OPTIMIZED_DIR E8_POOL PE_ROOT
"""
import hashlib
import json
import os
import sys

import pandas as pd

from optimized_attack import make_candidate, payload
from preservation_margin import stable_rng
from sda_common import tlsh_digest


def rebuild(record, root, row, stage, seed):
    with open(os.path.join(root, record.path), "rb") as handle:
        data = handle.read()
    padding_size = int(row.padding_size)
    variant = getattr(row, f"{stage}_padding")
    offset = int(getattr(row, f"{stage}_offset"))
    region_start = offset - padding_size if variant.startswith("pre_") else offset
    rng = stable_rng(seed, row.artifact_id, row.scope, int(row.payload_size), region_start, variant)
    mutant, payload_offset, changed = make_candidate(
        data, region_start, payload(int(row.payload_size)), padding_size, variant, rng
    )
    if payload_offset != offset or changed != getattr(row, f"{stage}_changed_bytes"):
        raise RuntimeError(f"{row.artifact_id}: la reconstrucción no coincide con lo almacenado")
    return data, mutant


def main():
    out, pool_path, root = sys.argv[1:4]
    with open(os.path.join(out, "config.json"), encoding="utf-8") as handle:
        seed = json.load(handle)["seed"]
    trials = pd.read_parquet(os.path.join(out, "trials"))
    pool = pd.read_parquet(pool_path).set_index("artifact_id")

    rows = []
    for (scope, size, algorithm), group in trials.groupby(["scope", "payload_size", "algorithm"]):
        row = {"scope": scope, "payload_size": size, "algorithm": algorithm, "artifacts": len(group)}
        for stage in ("baseline", "placement", "optimized"):
            comparable = group[group[f"{stage}_comparable"].eq(True)]
            row[f"{stage}_exact"] = int(comparable[f"{stage}_exact"].eq(True).sum())
            row[f"{stage}_saturated"] = int(comparable[f"{stage}_saturated"].eq(True).sum())
            row[f"{stage}_median_score"] = comparable[f"{stage}_score"].median()
        rows.append(row)
    counts = pd.DataFrame(rows)
    counts.to_csv(os.path.join(out, "exact_counts.csv"), index=False)
    print(counts.to_string(index=False))

    tlsh = trials[trials.algorithm == "tlsh"]
    winners = tlsh[tlsh.optimized_exact.eq(True)]
    for row in winners.itertuples(index=False):
        record = pool.loc[row.artifact_id]
        data, mutant = rebuild(record, root, row, "optimized", seed)
        if tlsh_digest(mutant) != record.tlsh or hashlib.sha256(mutant).digest() == hashlib.sha256(data).digest():
            raise RuntimeError(f"{row.artifact_id}: el ganador no conserva el TLSH o no cambia el fichero")
    print(f"\nTLSH exactos reconstruidos y verificados: {len(winners)}")
    print(f"bytes cambiados en ellos: mediana {winners.optimized_changed_bytes.median():.0f}, "
          f"mínimo {winners.optimized_changed_bytes.min()}, máximo {winners.optimized_changed_bytes.max()}")
    families = winners.optimized_padding.str.replace(r"^(pre|post)_", "", regex=True)
    print("relleno de esos ganadores:", families.value_counts().to_dict())

    distance_one = tlsh[tlsh.baseline_comparable.eq(True) & (tlsh.baseline_score == 1)]
    checksum_only = 0
    for row in distance_one.itertuples(index=False):
        record = pool.loc[row.artifact_id]
        _data, mutant = rebuild(record, root, row, "baseline", seed)
        digest = tlsh_digest(mutant)
        # Without "T1": checksum (2 hex), then length, quartile ratios and the 128 bucket codes.
        checksum_only += int(digest[2:] == record.tlsh[2:] and digest[:2] != record.tlsh[:2])
    print(f"baseline TLSH a distancia 1: {len(distance_one)}; solo difiere el checksum: {checksum_only}")


if __name__ == "__main__":
    main()
