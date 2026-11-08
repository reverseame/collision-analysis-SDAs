#!/bin/sh
# Packs into OUT the artifacts that do not fit in git, for deposit on Zenodo.
# Usage (on the experiment host): sh build_zenodo_bundle.sh /var/tmp/sda-work /var/tmp/sda-work/zenodo
#
# Files that contain bytes of Microsoft binaries, or the export of the source database, go only
# into restricted.tar.zst (restricted-access record); every other package excludes them.
set -eu
WORK=$1
OUT=$2
mkdir -p "$OUT"
RESTRICTED='^(e0/db_pages\.parquet|analysis/e3-pages/pool\.parquet|code/attack-simulation/dmps/|code/extraction-and-analysis/dmps\.zip)'

files() {
    (cd "$WORK" && find "$@" -type f -not -path '*/tmp/*' -print0 | sort -z)
}

pack() {
    name=$1
    filter=$2
    shift 2
    files "$@" | grep -z $filter -E "$RESTRICTED" > "$OUT/$name.list"
    (cd "$WORK" && xargs -0 sha256sum) < "$OUT/$name.list" > "$OUT/$name.files.sha256"
    (cd "$WORK" && tar --null --files-from=- --owner=0 --group=0 --numeric-owner \
        --mtime='2026-10-29 00:00:00' -cf -) < "$OUT/$name.list" |
        zstd -q -T0 -19 -o "$OUT/$name.tar.zst" -f
    rm "$OUT/$name.list"
}

pack e0-raw -v e0
pack e0-sum-best -v e0-sum-best
pack e0-heuristic -v e0-heuristic
pack e8-pe-index -v e8-pe-index
pack functions-index -v analysis/functions
pack restricted '' e0/db_pages.parquet analysis/e3-pages/pool.parquet \
    code/attack-simulation/dmps code/extraction-and-analysis/dmps.zip

docker image inspect sda-preservation --format '{{.Id}}' > "$OUT/sda-preservation.image-id"
docker save sda-preservation:latest | zstd -q -T0 -19 -o "$OUT/sda-preservation.docker.tar.zst" -f

(cd "$OUT" && sha256sum ./*.tar.zst ./*.files.sha256 ./*.image-id | sed 's# \./# #') > "$OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"
du -sh "$OUT"/*
