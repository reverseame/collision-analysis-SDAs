"""Re-score a sample of E2 exact collisions from the page bytes.

For each algorithm combination in collision_pairs.parquet, the script samples N pairs, reads
both pages from the corpus ZIPs, checks their SHA-256 against the pair, recomputes the three
digests and scores the pair with every algorithm. A pair confirms its combination when the
algorithms listed in `algos` give their maximum similarity (ssdeep or sdhash score 100, TLSH
distance 0) and the remaining algorithms do not.

Usage: python verify_collisions.py E0_DIR CORPUS COLLISION_PAIRS OUT_CSV [N] [SEED]
"""
import glob
import hashlib
import os
import sys
import tempfile
import zipfile

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import ssdeep

from sda_common import (
    MIN_SDHASH_FEATURES,
    full_sdbf,
    sdhash_features,
    sdhash_files,
    sdhash_scores,
    tlsh_digest,
    tlsh_distance,
)

PAGE = 4096
ALGOS = ("TLSH", "SSDEEP", "SDHASH")


def locate(e0, wanted):
    """First (zip, page_index) of every wanted SHA-256 in the E0 shards."""
    found = {}
    for path in sorted(glob.glob(os.path.join(e0, "shards", "*.parquet"))):
        frame = pq.read_table(path, columns=["zip", "page_index", "sha256"]).to_pandas()
        for row in frame[frame.sha256.isin(wanted)].itertuples(index=False):
            found.setdefault(bytes(row.sha256), (row.zip, int(row.page_index)))
        if len(found) == len(wanted):
            break
    missing = set(wanted) - set(found)
    if missing:
        raise RuntimeError(f"{len(missing)} contenidos no encontrados en {e0}")
    return found


def read_pages(corpus, places):
    pages = {}
    for zip_name, group in pd.Series(places).groupby(lambda sha: places[sha][0]):
        with zipfile.ZipFile(os.path.join(corpus, zip_name)) as archive:
            joined = archive.read("joinedModuleContents.dmp")
        for sha in group.index:
            start = places[sha][1] * PAGE
            data = joined[start:start + PAGE]
            if hashlib.sha256(data).digest() != sha:
                raise RuntimeError(f"{zip_name}, página {places[sha][1]}: SHA-256 distinto")
            pages[sha] = data
    return pages


def main(e0, corpus, pairs_path, out, n=6, seed=20261108):
    pairs = pd.read_parquet(pairs_path)
    pairs["sha256_a"] = pairs.sha256_a.map(bytes)
    pairs["sha256_b"] = pairs.sha256_b.map(bytes)
    rng = np.random.default_rng(seed)
    sample = pd.concat(
        group.iloc[rng.choice(len(group), size=min(n, len(group)), replace=False)]
        for _, group in pairs.groupby("algos", sort=True)
    ).reset_index(drop=True)

    wanted = sorted(set(sample.sha256_a) | set(sample.sha256_b))
    pages = read_pages(corpus, locate(e0, wanted))

    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, sha in enumerate(wanted):
            path = os.path.join(tmp, f"{i}.bin")
            with open(path, "wb") as handle:
                handle.write(pages[sha])
            paths.append(path)
        sdbf = dict(zip(wanted, sdhash_files(paths, include_scheme=True)))
    ssd = {sha: ssdeep.hash(pages[sha]) for sha in wanted}
    tl = {sha: tlsh_digest(pages[sha]) for sha in wanted}

    lines, comparable = [], []
    for row in sample.itertuples(index=False):
        a, b = sdbf[row.sha256_a], sdbf[row.sha256_b]
        ok = min(sdhash_features(a), sdhash_features(b)) >= MIN_SDHASH_FEATURES
        comparable.append(ok)
        if ok:
            lines.append(f"{full_sdbf(a)}\t{full_sdbf(b)}")
    scores = iter(sdhash_scores(lines))

    rows = []
    for row, ok in zip(sample.itertuples(index=False), comparable):
        a, b = row.sha256_a, row.sha256_b
        result = {
            "algos": row.algos,
            "ssdeep_score": ssdeep.compare(ssd[a], ssd[b]),
            "tlsh_dist": tlsh_distance(tl[a], tl[b]),
            "sdhash_score": next(scores) if ok else None,
        }
        maximal = {
            "SSDEEP": result["ssdeep_score"] == 100,
            "TLSH": result["tlsh_dist"] == 0,
            "SDHASH": result["sdhash_score"] == 100,
        }
        listed = set(row.algos.split("+"))
        result["confirmed"] = all(maximal[x] == (x in listed) for x in ALGOS)
        rows.append(result)
    frame = pd.DataFrame(rows)
    frame.to_csv(out, index=False)
    print(frame.groupby("algos").confirmed.agg(["size", "sum"]).to_string())
    print(f"confirmados: {int(frame.confirmed.sum())}/{len(frame)}")


if __name__ == "__main__":
    if len(sys.argv) not in (5, 6, 7):
        sys.exit(__doc__)
    main(*sys.argv[1:5], *(int(v) for v in sys.argv[5:]))
