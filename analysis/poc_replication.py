"""E6a: provenance and E1-style scoring of the published three-page PoC dumps.

Run after attack-simulation/generate_exploit.py and emulate.py. For each page it reports the
changed offsets, the ssdeep score, the TLSH distance and the sdhash score under the 16-feature
comparability rule, and then locates the original page by SHA-256 in each E0 index. The search
stops at the first ZIP holding each page; identical pages exist in other editions.

Usage: python poc_replication.py DMPS_DIR [E0_ROOT ...]
"""
import glob
import hashlib
import os
import sys

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

PAGES = (1, 2, 3)
SUFFIX = "_post_injection"


def score(dmps):
    paths = []
    for page in PAGES:
        paths += [os.path.join(dmps, f"page_{page}.dmp"), os.path.join(dmps, f"page_{page}{SUFFIX}.dmp")]
    sdbfs = sdhash_files(paths, include_scheme=True)
    hashes = {}
    for index, page in enumerate(PAGES):
        with open(paths[2 * index], "rb") as handle:
            original = handle.read()
        with open(paths[2 * index + 1], "rb") as handle:
            mutant = handle.read()
        left, right = sdbfs[2 * index], sdbfs[2 * index + 1]
        features = sdhash_features(left), sdhash_features(right)
        comparable = min(features) >= MIN_SDHASH_FEATURES
        ssdeep_left, ssdeep_right = ssdeep.hash(original), ssdeep.hash(mutant)
        tlsh_left, tlsh_right = tlsh_digest(original), tlsh_digest(mutant)
        digest = hashlib.sha256(original).digest()
        hashes[digest] = page
        print(f"página {page}: sha256 {digest.hex()}")
        print(f"  bytes cambiados {[i for i, (a, b) in enumerate(zip(original, mutant)) if a != b]}")
        print(f"  ssdeep {ssdeep.compare(ssdeep_left, ssdeep_right)} exacto {ssdeep_left == ssdeep_right}")
        print(f"  tlsh {tlsh_distance(tlsh_left, tlsh_right)} exacto {tlsh_left == tlsh_right}")
        sdhash_score = sdhash_scores([f"{full_sdbf(left)}\t{full_sdbf(right)}"])[0] if comparable else None
        print(
            f"  sdhash features {features} comparable {comparable} "
            f"puntuación {sdhash_score} exacto {left == right}"
        )
    return hashes


def trace(root, hashes):
    files = sorted(glob.glob(os.path.join(root, "shards", "*.parquet")))
    if not files:
        print(f"{root}: sin shards")
        return
    names = pq.read_schema(files[0]).names
    columns = [name for name in ("zip", "page_index", "sha256", "dereloc", "sdhash_features") if name in names]
    found = {}
    for path in files:
        frame = pq.read_table(path, columns=columns).to_pandas()
        for row in frame[frame.sha256.isin(list(hashes))].itertuples(index=False):
            found.setdefault(hashes[bytes(row.sha256)], (
                row.zip, int(row.page_index), getattr(row, "dereloc", None), int(row.sdhash_features),
            ))
        if len(found) == len(hashes):
            break
    print(f"{root}:")
    for page in PAGES:
        print(f"  página {page}: {found.get(page, 'no encontrada')}")


def main():
    dmps, roots = sys.argv[1], sys.argv[2:]
    hashes = score(dmps)
    for root in roots:
        trace(root, hashes)


if __name__ == "__main__":
    main()
