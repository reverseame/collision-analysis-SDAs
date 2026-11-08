# E0: per-page index of the corpus

Basis for the remaining experiments: it replaces the extraction by `module_id` from the database (which groups captures from several editions and assigns ~2% of pages to a module they do not belong to) with an index computed directly on the `win-module-extractor` ZIP files.

| Step | Script | Output |
|---|---|---|
| 1 | `build_index.py CORPUS OUT [WORKERS] [raw\|guided\|heuristic]` | `OUT/shards/*.parquet`, one per ZIP: zip, arch_dir, os_dir, module, base_address, page_index, sha256, tlsh, ssdeep, sdhash, sdhash_features, entropy, zero_starts, zero_lengths (runs of `0x00` ≥ 16 B), dereloc |
| 2 | `export_db.py OUT [HOST]` | `OUT/db_pages.parquet`: pages of the `dataset` database with module and OS |
| 3 | `join_db.py OUT` | `OUT/page_map.parquet`: for each `page_id`, the ZIP and page holding its content (`match` = `file_path`, `modulo`, `corpus` or `sin_match`) and how many distinct contents share its digest triple |

Pages are 4096 B chunks of `joinedModuleContents.dmp`; `page_index` matches `pages.num_page`. Digests use the database format: TLSH without `T1` (`-` if it cannot be computed) and sdhash from the size field onwards (in the database: `sdbf:03:0::` + that value).

## Derelocation (`dereloc.py`)

The `dataset` database is computed on non-derelocated pages (`preprocess_method = Raw`). With ASLR, two legitimate captures of the same module and build differ in every relocated field, and in 32-bit code that is enough for ssdeep and sdhash to give 0 (see `../analysis/README.md`, E1). For that reason the index can also be built on derelocated images:

- `sum-best` (and `sum-guide`, `sum-linear`): SUM derelocation (`reverseame/similarity-unrelocated-module@127d4fb`, the submodule of `reverseame/sum-plugin`; in `/opt/sum` in the image) with its default criterion: `guide` if the image has a `.reloc` readable in memory and `linear` otherwise. `linear` is the engine's linear sweep, unchanged. `guide` is the same algorithm applied in place on a `bytearray`, because the engine as is cannot be used on the corpus:
  - Quadratic cost: `guided_derelocation` and `set_zero_*` rebuild `pe.__data__` (immutable bytes) on every relocation entry. On the largest modules, 178–1741 s per module versus 0.02–0.12 s in place (32-bit `mshtml.dll`, 20 MB: 29 min).
  - Failures building `MarkedPE` in 127 of 3000 ZIP files (4.2%): 121 64-bit (`AttributeError` in `__UNWIND_INFO`: `__unpack_data__` returns `None` and it is not checked) and 6 32-bit (`TypeError`).
  - Its test `test_guided_is_relocation_invariant` fails with a real module (`IndexError` in `MarkedPE.set_visited`); `test_raw_and_linear_run_and_differ` passes.

  Where the engine finishes, the output is byte-for-byte identical (60/60, 254/254 and 4/4 large modules). Per-ZIP status in the `dereloc` column: `guide`, `linear`, `sin_reloc`, `sin_pe` or `error_linear` (`../analysis/drift_baseline.py` excludes the last two).
- `heuristic`: replaces 4/8 B values within the module's range with their offset from the base.

In a sample of 400 ZIP files, `sum-best` uses `guide` in 91.5% and `linear` in 8.5% (modules without `.reloc`, median 12 KB, ≤ 0.5 s each).

On the experiment host (freya): `/work/e0` (raw), `/work/e0-sum-best`, `/work/e0-heuristic`.

On freya (see `../container/README.md`):

```bash
U="$(id -u):$(id -g)"
docker run -d --name sda-e0 --cpus 12 --network sda-net --user "$U" \
  -v /mnt/DATASETS/modules-Windows:/data/modules-Windows:ro -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/e0_index && nice -n 10 python build_index.py /data/modules-Windows /work/e0 12 > /work/e0/build_index.out 2>&1"
docker run --rm --network sda-net --user "$U" -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/e0_index && python export_db.py /work/e0 && python join_db.py /work/e0"
```
