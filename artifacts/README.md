# Artifacts of E0–E8

`analysis/` is a copy of `/var/tmp/sda-work/analysis` on the experiment host (freya) after the
runs documented in [`../analysis/README.md`](../analysis/README.md), without smoke tests or
temporary directories. Mounting it at `/work/analysis` reproduces the paths of those commands:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/analysis:/work/code/analysis" \
  -v "$PWD/artifacts/analysis:/work/analysis" sda-preservation
```

| Path | Content |
|---|---|
| `e1_pairs.parquet`, `e1_thresholds.csv`, `sum-best/`, `heuristic/` | E1 on raw pages, with SUM and with the heuristic |
| `collision_pairs.parquet`, `collision_groups.parquet`, `e2_collision_check.csv` | E2 and its verification against the page bytes |
| `null_blocks_*.json` | null runs |
| `e3-pages/` | E3: trials, `config.json`; `pool.parquet` (4250 SUM pages with their bytes) only in the restricted record |
| `e4-optimized/`, `e5-mechanisms/` | E4 and E5 |
| `tlsh-position/`, `tlsh-position.out` | why TLSH tolerates writes at the start of a page |
| `e6-chains/`, `e6-poc-replication.out`, `smbghost-fragments.out` | E6 |
| `e7-countermeasures/`, `e7-countermeasures.out` | E7: policies, rules and their combination |
| `e8-pe/` | E8: legitimate pairs, thresholds, pool and trials; `optimized/`, the E4 optimized attack on complete PE files |
| `functions/` | functions: overlap with the caves, drift of exports and preservation when writing inside the function. The function index itself is the Zenodo package `functions-index` |
| `logs/` | outputs of E0, of the PE index and of the search for the proof-of-concept pages |
| `environment.txt` | versions inside the image and ID of the image used |

## Zenodo

Artifacts that do not fit in git are packed with
[`build_zenodo_bundle.sh`](build_zenodo_bundle.sh) (run on the experiment host,
`/var/tmp/sda-work/zenodo`). DOI pending.

Public record (5.0 GB). These packages contain only digests, SHA-256 values and metadata; no
bytes of binaries:

| File | Content |
|---|---|
| `e0-raw.tar.zst` | raw E0 index and `page_map.parquet` |
| `e0-sum-best.tar.zst`, `e0-heuristic.tar.zst` | de-relocated E0 indexes |
| `e8-pe-index.tar.zst` | index of the E8 PE files |
| `functions-index.tar.zst` | function ranges and exports of the E8 pool (`analysis/functions`) |
| `sda-preservation.docker.tar.zst` | `docker save` of the image used |

Restricted record (0.84 GB), available for research upon request:

| File | Content |
|---|---|
| `restricted.tar.zst` | `e0/db_pages.parquet` (export of the source database `dataset`), `analysis/e3-pages/pool.parquet` (bytes of the E3 pages), `code/attack-simulation/dmps/` (pages of the proof of concept) and `code/extraction-and-analysis/dmps.zip` (pages of the conference version) |

[`zenodo/SHA256SUMS`](zenodo/SHA256SUMS) pins every package and the `*.files.sha256` manifests
uploaded with them, which list the SHA-256 of each packed file.
[`zenodo/sda-preservation.image-id`](zenodo/sda-preservation.image-id) is the ID of the saved
image. Packages are extracted into the working directory (`/work`), with this repository at
`/work/code`:

```bash
sha256sum -c --ignore-missing SHA256SUMS
for f in e0-raw e0-sum-best e0-heuristic e8-pe-index functions-index; do
  zstd -dc $f.tar.zst | tar -xf - -C /var/tmp/sda-work
done
zstd -dc restricted.tar.zst | tar -xf - -C /var/tmp/sda-work   # restricted record only
zstd -dc sda-preservation.docker.tar.zst | docker load
```
