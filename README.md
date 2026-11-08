# collision-analysis-SDAs

Code, results and reproduction instructions for the article *Hiding Behind Similarity:
Adversarial Similarity Preservation in `ssdeep`, `sdhash`, and `TLSH`* (Luis Palazón Simón and
Ricardo J. Rodríguez, Universidad de Zaragoza; submitted to *Computers & Security*).

Similarity digest algorithms (SDAs, or fuzzy hashes) are used to recognize variants of known
content, sometimes treating high similarity to a known benign artifact as evidence of
benignness. *Adversarial similarity preservation* inserts malicious code into a benign artifact
while keeping its digest identical or highly similar. This repository measures that attack
against `ssdeep`, `sdhash` and `TLSH` on 4,629,285 memory pages of Windows system modules
(39,002 module captures) and on 31,265 Windows PE files, and evaluates two countermeasures.

## Layout

| Path | Content |
|---|---|
| [`container/`](container/) | Docker image `sda-preservation` with pinned `sdhash` 3.4, `ssdeep`, `py-tlsh` 4.7.2, `unicorn`, `capstone` and the SUM de-relocation engine |
| [`e0_index/`](e0_index/) | E0: per-page index of the corpus (SHA-256, the three digests, entropy, null runs) on raw and de-relocated pages |
| [`analysis/`](analysis/) | E1–E8 and supporting analyses; its README documents every command and result table |
| [`artifacts/`](artifacts/) | Complete outputs of E1–E8 (Parquet trial files, CSV, logs, environment) and the script that builds the Zenodo bundle |
| [`attack-simulation/`](attack-simulation/), [`extraction-and-analysis/`](extraction-and-analysis/), [`graphs/`](graphs/) | Code of the conference version (Unicorn proof of concept, database-based extraction, figures) |

## Experiments

| ID | Question | Script (`analysis/` unless noted) | Outputs (`artifacts/analysis/`) |
|---|---|---|---|
| E0 | Per-page index of the corpus | `e0_index/build_index.py`, `export_db.py`, `join_db.py` | Zenodo: `e0-raw`, `e0-sum-best`, `e0-heuristic`; `logs/` |
| — | Null runs (≥ 16 B of `0x00`) per page quarter | `null_blocks.py` | `null_blocks_*.json` |
| E1 | Legitimate drift and acceptance thresholds τ95/τ99 | `drift_baseline.py` | `e1_*`, `sum-best/`, `heuristic/` |
| E2 | Exact digest collisions in the corpus | `exact_collisions.py`, `verify_collisions.py` | `collision_*.parquet`, `e2_collision_check.csv` |
| E3 | Preservation margin of a single write | `preservation_margin.py pages` | `e3-pages/` |
| E4 | Optimized attack (position and padding search) | `optimized_attack.py` | `e4-optimized/` |
| E5 | Internal mechanism of each SDA | `mechanism_analysis.py`, `tlsh_position.py` | `e5-mechanisms/`, `tlsh-position/` |
| E6 | Fragmented payload chained across pages | `chain_attack.py`, `poc_replication.py`, `smbghost_fragments.py` | `e6-chains/`, `e6-poc-replication.out`, `smbghost-fragments.out` |
| E7 | Countermeasures: cross-algorithm policies and byte rules | `countermeasures.py` | `e7-countermeasures/` |
| E8 | Generalization to complete PE files and functions | `pe_index.py`, `pe_drift_baseline.py`, `preservation_margin.py pe`, `optimized_attack.py --mode pe`, `pe_optimized_check.py`, `pe_cave_mapping.py`, `function_analysis.py` | `e8-pe/`, `functions/`; Zenodo: `e8-pe-index`, `functions-index` |

Aggregate tables used in the article are also in [`analysis/results/`](analysis/results/).

## Reproducing

All experiments run in the `sda-preservation` image (see [`container/README.md`](container/README.md)).
The exact image used is part of the Zenodo bundle (`sda-preservation.docker.tar.zst`, image ID
in [`artifacts/zenodo/sda-preservation.image-id`](artifacts/zenodo/sda-preservation.image-id)).
Commands in [`analysis/README.md`](analysis/README.md) mount the working directory at `/work`
with this repository at `/work/code`.

What can be re-run depends on the inputs available:

| Inputs | Re-runnable |
|---|---|
| This repository | Inspection and re-aggregation of every result from the stored trial files |
| + public Zenodo bundle (indexes and image) | Null runs, E1, E2 (`exact_collisions.py`), E8 drift baseline |
| + restricted Zenodo record | E4, E5 (including `tlsh_position.py`), E6, the PoC replication |
| + corpus of module captures | E0, E3, E7, `verify_collisions.py` |
| + PE files and radare2 function listings | E8 mutation experiments and function analysis |

The corpus of module captures (ZIP files produced by
[win-module-extractor](https://github.com/reverseame/win-module-extractor)) and the PE files are
Microsoft system binaries and are not redistributed. The Zenodo bundle contains only digests,
SHA-256 values and metadata. Files that contain bytes of Windows binaries (the E3 page pool, the
pages of the proof of concept) and the export of the source database are deposited in a
restricted-access record, available for research upon request. Details and checksums:
[`artifacts/README.md`](artifacts/README.md).

## Related repositories

- [win-module-extractor](https://github.com/reverseame/win-module-extractor), [win-module-analyzer](https://github.com/reverseame/win-module-analyzer) and [win-module-database](https://github.com/reverseame/win-module-database): construction of the corpus and the source database.
- [similarity-unrelocated-module](https://github.com/reverseame/similarity-unrelocated-module) (SUM): de-relocation of Windows modules, used for E0 and E1.
- [APOTHEOSIS](https://github.com/reverseame/APOTHEOSIS): approximate search over similarity digests, used in the conference version.

## License

Code: GNU General Public License v3.0 ([`LICENSE`](LICENSE)). Result files in `artifacts/` and
`analysis/results/`: CC BY 4.0. If you use them, please cite the article (see
[`CITATION.cff`](CITATION.cff)).
