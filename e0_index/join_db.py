"""Joins the pages of the `dataset` database with the E0 index by the digest triple.

It does not trust modules.file_path / module_id (some pages are assigned to another module).
For each page_id it chooses, by priority:
  file_path   the ZIP indicated by modules.file_path, same page (page_index == num_page)
  modulo      another ZIP of the same module (another edition or architecture), same page
  corpus      any page of the corpus with the same triple (TLSH, ssdeep, sdhash)
  sin_match   none
and records how many distinct contents (SHA-256) share that triple in the corpus.

Usage: python join_db.py E0_DIR
Output: E0_DIR/page_map.parquet
"""
import glob
import hashlib
import os
import re
import sys

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

INDEX_COLS = ["zip", "page_index", "sha256", "tlsh", "ssdeep", "sdhash", "module"]
OUT_COLS = ["page_id", "num_page", "zip", "page_index", "sha256", "key", "match"]


def triple_key(df):
    return [hashlib.sha1(f"{a}|{b}|{c}".encode()).digest() for a, b, c in zip(df.tlsh, df.ssdeep, df.sdhash)]


def load_index(e0):
    idx = pa.concat_tables(
        [pq.read_table(f, columns=INDEX_COLS) for f in sorted(glob.glob(os.path.join(e0, "shards", "*.parquet")))]
    ).to_pandas()
    idx["key"] = triple_key(idx)
    idx["zip_base"] = idx.zip.str.rsplit("/", n=1).str[-1]
    idx["stem"] = idx.module.str.lower()
    return idx.drop(columns=["tlsh", "ssdeep", "sdhash", "module"])


def load_db(e0):
    db = pq.read_table(os.path.join(e0, "db_pages.parquet"),
                       columns=["page_id", "num_page", "tlsh", "ssdeep", "sdhash", "file_path"]).to_pandas()
    db["key"] = triple_key(db)
    db["zip_base"] = db.file_path.map(lambda p: re.sub(r"_(Intel|Other)_\w+\.json$", "", p) + ".zip")
    db["stem"] = db.file_path.str.split("_").str[0].str.lower()
    return db.drop(columns=["tlsh", "ssdeep", "sdhash", "file_path"])


def same_page(rest, idx, scope, name):
    """Pages whose triple is at the same position (num_page) of a ZIP of `scope`."""
    right = idx.drop_duplicates(subset=[scope, "page_index", "key"])[[scope, "page_index", "key", "zip", "sha256"]]
    m = rest.merge(right, left_on=[scope, "num_page", "key"], right_on=[scope, "page_index", "key"], how="inner")
    return m.assign(match=name)[OUT_COLS]


def anywhere(rest, idx):
    """Pages whose triple appears at any position of the corpus."""
    right = idx.drop_duplicates(subset=["key"])[["key", "zip", "page_index", "sha256"]]
    return rest.merge(right, on="key", how="inner").assign(match="corpus")[OUT_COLS]


def main():
    e0 = sys.argv[1]
    idx = load_index(e0)
    db = load_db(e0)
    contents = idx.groupby("key").sha256.nunique().rename("contenidos_por_terna")

    picked, rest = [], db
    for step in (lambda r: same_page(r, idx, "zip_base", "file_path"),
                 lambda r: same_page(r, idx, "stem", "modulo"),
                 lambda r: anywhere(r, idx)):
        hit = step(rest)
        picked.append(hit)
        rest = rest[~rest.page_id.isin(hit.page_id)]
    miss = rest.assign(zip=None, page_index=None, sha256=None, match="sin_match")[OUT_COLS]

    out = pd.concat(picked + [miss], ignore_index=True)
    out = out.merge(contents, left_on="key", right_index=True, how="left").drop(columns=["key"])
    out = out.sort_values("page_id")
    pq.write_table(pa.Table.from_pandas(out, preserve_index=False),
                   os.path.join(e0, "page_map.parquet"), compression="zstd")
    print(out.match.value_counts().to_string())
    print("páginas de la BD:", len(db), "| filas en page_map:", len(out))
    print("ternas del corpus con más de un contenido distinto:", int((contents > 1).sum()))


if __name__ == "__main__":
    main()
