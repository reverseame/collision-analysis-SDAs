"""Null blocks (runs of 0x00 >= 16 B) in the database pages, from the E0 index.

Writes two JSON files with the structure of graphs/null_blocks_results.json (input of graphs/violin.py):
  null_blocks_terminated.json  only runs that end before the end of the page (criterion that
                               reproduces the paper's numbers)
  null_blocks_all.json         all runs, including those that reach the end of the page
Keys: first..fourth = no. of blocks starting in each quarter; sizes_counter_q1..q4 = sizes per
quarter; zero / sizes_counter_q0 = blocks starting at byte 0.
It also prints how many pages have their first 16 bytes null and how many are entirely null.

Usage: python null_blocks.py E0_DIR OUT_DIR
"""
import collections
import glob
import json
import os
import sys

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

PAGE = 4096
QUARTER = PAGE // 4


def db_weights(e0):
    """No. of database pages that point to each (zip, page_index) of the index."""
    pm = pq.read_table(os.path.join(e0, "page_map.parquet"), columns=["zip", "page_index"]).to_pandas()
    pm = pm.dropna(subset=["zip"])
    return pm.groupby(["zip", "page_index"]).size().rename("weight").reset_index()


def main():
    e0, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    weights = db_weights(e0)
    idx = pa.concat_tables([pq.read_table(f, columns=["zip", "page_index", "zero_starts", "zero_lengths"])
                            for f in sorted(glob.glob(os.path.join(e0, "shards", "*.parquet")))])
    keys = idx.select(["zip", "page_index"]).to_pandas()
    keys["page_index"] = keys.page_index.astype("int64")
    weights["page_index"] = weights.page_index.astype("int64")
    w = keys.merge(weights, on=["zip", "page_index"], how="left").weight.fillna(0).to_numpy(np.int64)
    pages = int(w.sum())

    starts = idx.column("zero_starts").combine_chunks()
    lengths = idx.column("zero_lengths").combine_chunks()
    parent = pc.list_parent_indices(starts).to_numpy()
    s = pc.list_flatten(starts).to_numpy().astype(np.int64)
    l = pc.list_flatten(lengths).to_numpy().astype(np.int64)
    bw = w[parent]

    first16 = np.zeros(len(w), dtype=bool)
    first16[parent[(s == 0) & (l >= 16)]] = True
    full = np.zeros(len(w), dtype=bool)
    full[parent[(s == 0) & (l == PAGE)]] = True
    print(f"páginas de la BD: {pages}")
    print(f"páginas con los primeros 16 B nulos: {int(w[first16].sum())} ({100 * w[first16].sum() / pages:.2f} %)")
    print(f"páginas enteramente nulas: {int(w[full].sum())}")

    for name, keep in (("terminated", s + l < PAGE), ("all", np.ones_like(s, dtype=bool))):
        ss, ll, ww = s[keep], l[keep], bw[keep]
        q = ss // QUARTER
        res = {}
        for qi, label in enumerate(("first", "second", "third", "fourth")):
            res[label] = int(ww[q == qi].sum())
        res["zero"] = int(ww[ss == 0].sum())
        for qi, mask in enumerate((ss == 0, q == 0, q == 1, q == 2, q == 3)):
            c = collections.Counter()
            for size, weight in zip(ll[mask], ww[mask]):
                c[int(size)] += int(weight)
            res[f"sizes_counter_q{qi}"] = {str(k): v for k, v in sorted(c.items())}
        total = sum(res[k] for k in ("first", "second", "third", "fourth"))
        print(f"[{name}] bloques: {total} | por cuarto: "
              + ", ".join(f"{k}={res[k]} ({100 * res[k] / total:.1f} %)" for k in ("first", "second", "third", "fourth"))
              + f" | desde el byte 0: {res['zero']}")
        with open(os.path.join(out, f"null_blocks_{name}.json"), "w") as fh:
            json.dump(res, fh)


if __name__ == "__main__":
    main()
