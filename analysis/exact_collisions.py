"""E2: exact collisions between distinct contents of the corpus, per algorithm.

Unit: distinct page content (SHA-256) of the E0 index. A collision of an algorithm is a
pair of distinct contents with the same digest. Non-comparable digests are excluded:
TLSH "-" (TLSH does not compute it) and sdhash with fewer than 16 features (sdhash 3.4 scores 0 even
against itself). For ssdeep, minimum-block-size digests (prefix "3:") are reported separately.

Outputs in OUT_DIR:
  collision_groups.parquet  groups (algorithm, digest, no. of contents)
  collision_pairs.parquet   content pairs and the algorithms in which they collide
Usage: python exact_collisions.py E0_DIR OUT_DIR
"""
import glob
import os
import sys

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

MIN_SDHASH_FEATURES = 16
MAX_PAIR_GROUP = 5000
ALGOS = ("tlsh", "ssdeep", "sdhash")


def load_contents(e0):
    idx = pa.concat_tables([pq.read_table(f, columns=["sha256", "tlsh", "ssdeep", "sdhash", "sdhash_features"])
                            for f in sorted(glob.glob(os.path.join(e0, "shards", "*.parquet")))]).to_pandas()
    u = idx.drop_duplicates("sha256").reset_index(drop=True)
    u["cid"] = np.arange(len(u), dtype=np.int64)
    return len(idx), u


def comparable(u, algo):
    if algo == "tlsh":
        return u.tlsh != "-"
    if algo == "sdhash":
        return u.sdhash_features >= MIN_SDHASH_FEATURES
    return pd.Series(True, index=u.index)


def pairs_of(groups):
    """Pairs (cid_a < cid_b) within each group, encoded as a * N + b."""
    out = []
    for cids in groups:
        c = np.sort(np.asarray(cids, dtype=np.int64))
        a, b = np.triu_indices(len(c), k=1)
        out.append(np.stack([c[a], c[b]], axis=1))
    return np.concatenate(out) if out else np.empty((0, 2), dtype=np.int64)


def main():
    e0, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    n_pages, u = load_contents(e0)
    print(f"páginas en el índice: {n_pages} | contenidos distintos: {len(u)}")
    print(f"no comparables: TLSH '-' = {(u.tlsh == '-').sum()}, "
          f"sdhash < {MIN_SDHASH_FEATURES} features = {(u.sdhash_features < MIN_SDHASH_FEATURES).sum()}")

    group_rows, pair_sets = [], {}
    for algo in ALGOS:
        sub = u[comparable(u, algo)]
        g = sub.groupby(algo).cid.agg(list)
        g = g[g.map(len) > 1]
        sizes = g.map(len)
        npairs = int((sizes * (sizes - 1) // 2).sum())
        line = (f"{algo}: grupos={len(g)} contenidos={int(sizes.sum())} pares={npairs} "
                f"grupo_max={int(sizes.max()) if len(g) else 0}")
        if algo == "ssdeep":
            low = g.index.str.startswith("3:")
            line += f" | de ellos con dígest de bloque mínimo ('3:'): grupos={int(low.sum())} pares={int((sizes[low] * (sizes[low] - 1) // 2).sum())}"
        print(line, flush=True)
        group_rows.append(pd.DataFrame({"algo": algo, "digest": g.index, "contents": sizes.to_numpy()}))
        big = sizes > MAX_PAIR_GROUP
        if big.any():
            print(f"   {int(big.sum())} grupos de más de {MAX_PAIR_GROUP} contenidos: se cuentan, pero sus pares "
                  f"no se generan ({int((sizes[big] * (sizes[big] - 1) // 2).sum())} pares)", flush=True)
        pair_sets[algo] = pairs_of(g[~big].to_list())

    pq.write_table(pa.Table.from_pandas(pd.concat(group_rows, ignore_index=True), preserve_index=False),
                   os.path.join(out, "collision_groups.parquet"), compression="zstd")

    n = np.int64(len(u))
    encoded = {a: np.unique(p[:, 0] * n + p[:, 1]) for a, p in pair_sets.items()}
    allp = np.unique(np.concatenate(list(encoded.values())))
    flags = {a: np.isin(allp, encoded[a]) for a in ALGOS}
    pairs = pd.DataFrame({"cid_a": allp // n, "cid_b": allp % n, **flags})
    labels = pd.Series("", index=pairs.index)
    for a in ALGOS:
        labels = labels + np.where(pairs[a], a.upper() + "+", "")
    pairs["algos"] = labels.str.rstrip("+")
    print("pares de contenidos distintos por combinación de algoritmos:")
    print(pairs.algos.value_counts().to_string())
    pairs = pairs.merge(u[["cid", "sha256"]].rename(columns={"cid": "cid_a", "sha256": "sha256_a"}), on="cid_a")
    pairs = pairs.merge(u[["cid", "sha256"]].rename(columns={"cid": "cid_b", "sha256": "sha256_b"}), on="cid_b")
    pq.write_table(pa.Table.from_pandas(pairs, preserve_index=False),
                   os.path.join(out, "collision_pairs.parquet"), compression="zstd")


if __name__ == "__main__":
    main()
