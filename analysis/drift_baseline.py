"""E1: baseline of legitimate drift between captures of the same module and build.

Pairs: the same module captured in the Standard and Datacenter editions of the same build and architecture
(Windows Server 2012 R2, 2016 and 2019; 32 and 64 bits), page by page (same page_index). The two
captures differ only by ASLR and by the state of each boot. Duplicate "(1)" ZIPs and modules whose
captures do not have the same number of pages are discarded.

Per page pair: identical (SHA-256), ssdeep (0-100), tlsh (distance; empty if either digest is
"-"), sdhash (0-100 with sdhash-pairs; empty if either page has < 16 features).
Threshold tau_p: value that accepts p% of the legitimate pairs (percentile 100-p of the ssdeep/sdhash
score, percentile p of the TLSH distance).

Outputs: OUT/e1_pairs.parquet, OUT/e1_thresholds.csv
Usage: python drift_baseline.py E0_DIR OUT_DIR [WORKERS]
"""
import glob
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep
import tlsh

MIN_SDHASH_FEATURES = 16
EDITION = re.compile(r"(Standard|Datacenter)")
COLS = ["zip", "arch_dir", "os_dir", "module", "page_index", "sha256", "tlsh", "ssdeep", "sdhash", "sdhash_features"]


def load_pairs(e0):
    files = sorted(glob.glob(os.path.join(e0, "shards", "*.parquet")))
    cols = COLS + (["dereloc"] if "dereloc" in pq.read_schema(files[0]).names else [])
    idx = pa.concat_tables([pq.read_table(f, columns=cols) for f in files]).to_pandas()
    idx = idx[~idx.zip.str.contains(r"\(1\)", regex=True)]
    if "dereloc" in idx:
        # Modules that could not be derelocated (engine failure or no PE header): their pages
        # remain raw and are not comparable with the rest.
        bad = idx.dereloc.str.startswith("error_") | (idx.dereloc == "sin_pe")
        print("estado de desreubicación (ZIP):", idx.drop_duplicates("zip").dereloc.value_counts().to_dict(), flush=True)
        idx = idx[~bad]
    ed = idx.os_dir.str.extract(EDITION, expand=False)
    idx = idx[ed.notna()].assign(edition=ed[ed.notna()])
    idx["build"] = idx.os_dir.str.replace(EDITION, "", regex=True)
    idx["mod"] = idx.module.str.lower()
    key = ["arch_dir", "build", "mod"]

    zips = idx.groupby(key + ["edition"]).agg(zip=("zip", "first"), n_zips=("zip", "nunique"),
                                              n_pages=("page_index", "size")).reset_index()
    std = zips[zips.edition == "Standard"].drop(columns="edition")
    dc = zips[zips.edition == "Datacenter"].drop(columns="edition")
    mods = std.merge(dc, on=key, suffixes=("_std", "_dc"))
    print(f"módulos con captura Standard y Datacenter: {len(mods)}", flush=True)
    mods = mods[mods.n_pages_std == mods.n_pages_dc]
    print(f"  con el mismo número de páginas: {len(mods)}", flush=True)

    side = ["zip", "page_index", "sha256", "tlsh", "ssdeep", "sdhash", "sdhash_features"]
    a = mods[key + ["zip_std"]].merge(idx[side], left_on="zip_std", right_on="zip").drop(columns=["zip", "zip_std"])
    b = mods[key + ["zip_dc"]].merge(idx[side], left_on="zip_dc", right_on="zip").drop(columns=["zip", "zip_dc"])
    return a.merge(b, on=key + ["page_index"], suffixes=("_a", "_b"))


def sdhash_scores(lines, workers):
    chunks = np.array_split(np.asarray(lines, dtype=object), max(1, workers))

    def run(chunk):
        if len(chunk) == 0:
            return []
        out = subprocess.run(["sdhash-pairs"], input="\n".join(chunk) + "\n",
                             capture_output=True, text=True, check=True).stdout
        return [int(x) for x in out.split()]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [s for part in pool.map(run, chunks) for s in part]


def main():
    e0, out = sys.argv[1], sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    os.makedirs(out, exist_ok=True)
    p = load_pairs(e0)
    print(f"pares de páginas: {len(p)}", flush=True)

    p["identical"] = p.sha256_a == p.sha256_b
    p["ssdeep_score"] = [ssdeep.compare(x, y) for x, y in zip(p.ssdeep_a, p.ssdeep_b)]
    ok_t = (p.tlsh_a != "-") & (p.tlsh_b != "-")
    p["tlsh_dist"] = np.nan
    p.loc[ok_t, "tlsh_dist"] = [tlsh.diff("T1" + x, "T1" + y) for x, y in zip(p.tlsh_a[ok_t], p.tlsh_b[ok_t])]
    ok_s = (p.sdhash_features_a >= MIN_SDHASH_FEATURES) & (p.sdhash_features_b >= MIN_SDHASH_FEATURES)
    p["sdhash_score"] = np.nan
    lines = [f"sdbf:03:0::{x}\tsdbf:03:0::{y}" for x, y in zip(p.sdhash_a[ok_s], p.sdhash_b[ok_s])]
    p.loc[ok_s, "sdhash_score"] = sdhash_scores(lines, workers)

    keep = ["arch_dir", "build", "mod", "page_index", "identical", "ssdeep_score", "tlsh_dist", "sdhash_score"]
    pq.write_table(pa.Table.from_pandas(p[keep], preserve_index=False), os.path.join(out, "e1_pairs.parquet"),
                   compression="zstd")

    print(f"páginas idénticas (SHA-256): {p.identical.sum()} de {len(p)} ({100 * p.identical.mean():.1f} %)")
    rows = []
    for subset, mask in (("todos", np.ones(len(p), bool)), ("no_identicos", ~p.identical.to_numpy())):
        for algo, col, higher_better in (("ssdeep", "ssdeep_score", True), ("tlsh", "tlsh_dist", False),
                                         ("sdhash", "sdhash_score", True)):
            v = p.loc[mask, col].dropna().to_numpy()
            row = {"pares": subset, "algoritmo": algo, "n": len(v), "comparables_%": 100 * len(v) / mask.sum(),
                   "mediana": np.median(v)}
            for acc in (90, 95, 99):
                row[f"tau_{acc}"] = np.percentile(v, 100 - acc if higher_better else acc)
            rows.append(row)
    th = pd.DataFrame(rows)
    th.to_csv(os.path.join(out, "e1_thresholds.csv"), index=False)
    print(th.to_string(index=False, float_format=lambda x: f"{x:.1f}"))


if __name__ == "__main__":
    main()
