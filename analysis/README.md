# Analyses over the E0 index

They require `../e0_index` to have been run already (`/var/tmp/sda-work/e0` on the experiment host (freya)). They run in the `sda-preservation` image:

```bash
docker run --rm --cpus 4 --user "$(id -u):$(id -g)" -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python null_blocks.py /work/e0 /work/analysis && python exact_collisions.py /work/e0 /work/analysis && python drift_baseline.py /work/e0 /work/analysis 8"
```

## `null_blocks.py`: null blocks (runs of `0x00` ≥ 16 B)

Over the 4,224,710 pages in the database whose content was located. Produces `null_blocks_terminated.json` (only runs that end before the end of the page, the criterion that reproduces the paper's distribution) and `null_blocks_all.json` (all runs), with the structure expected by `../graphs/violin.py`. Copies in `results/` alongside the `violin_e0_*.pdf` figures.

| | Paper | E0 (terminated) | E0 (all) |
|---|---|---|---|
| Blocks | 4,059,080 | 16,590,857 | 17,019,087 |
| 1st / 2nd / 3rd / 4th quarter | 28.0 / 24.9 / 24.3 / 22.7% | 27.8 / 24.9 / 24.4 / 22.9% | 27.8 / 24.7 / 24.1 / 23.5% |
| Pages with the first 16 B null | "more than 200,000" | 197,832 (4.68%) | |

The paper's counts are ~¼ of those of the full database: the original analysis was done on a subsample (probably `/home/luis/bd/extraction/1M_pages`, 1,111,937 pages).

## `exact_collisions.py`: E2, exact collisions

Unit: distinct page content (2,618,589 SHA-256 values among the 4,629,285 pages of the corpus). Collision: two distinct contents with the same digest, counting only comparable digests (TLSH `-` and sdhash with < 16 features are excluded). Outputs: `collision_groups.parquet` and `collision_pairs.parquet` (on freya, `/var/tmp/sda-work/analysis`).

| Combination | Pairs | Paper |
|---|---|---|
| sdhash only | 54,818 | 0 |
| ssdeep only | 29,361 | 0 |
| ssdeep + sdhash | 1,509 | 0 |
| TLSH only | 106 | 51 |
| TLSH + sdhash | 54 | 87 |
| TLSH + ssdeep | 11 | 3 |
| All three | 8 | |

Per algorithm: TLSH 179 pairs; ssdeep 30,889 (20,367 with minimum block-size digest `3:`); sdhash 56,389.

`verify_collisions.py` checks a sample against the bytes: it takes 6 pairs per combination (seed `20261108`), rereads both pages from the ZIPs, verifies their SHA-256, recomputes the three digests and scores each pair with the three algorithms. The algorithms in the combination always give score 100 or TLSH distance 0 (42/42). Since a score of 100 does not require identical digests, an algorithm outside the combination can also reach it: in one TLSH-only pair, sdhash gives 100 with different digests. Output: `results/e2_collision_check.csv`.

```bash
docker run --rm --cpus 4 --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/modules-Windows:/data/modules-Windows:ro -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python verify_collisions.py /work/e0 /data/modules-Windows \
    /work/analysis/collision_pairs.parquet /work/analysis/e2_collision_check.csv"
```

## `drift_baseline.py`: E1, legitimate drift baseline

Pairs: the same module in the Standard and Datacenter editions of the same build and architecture (Server 2012 R2, 2016 and 2019), page by page. 14,365 modules, 1,710,855 page pairs. sdhash is scored with `sdhash-pairs` (container image). It runs on each index (`/work/e0`, `/work/e0-sum-best`, `/work/e0-heuristic`; see `../e0_index/README.md`). Outputs: `e1_pairs.parquet` (freya) and `results/e1_thresholds_{raw,sum-best,heuristic}.csv`.

τp is the value accepted by p% of the legitimate pairs (for ssdeep and sdhash, minimum score; for TLSH, maximum distance). All pairs:

| Preprocessing | Identical pages | ssdeep τ95 / τ99 | TLSH τ95 / τ99 | sdhash τ95 / τ99 |
|---|---|---|---|---|
| Raw | 74.4% | 0 / 0 | 151 / 253 | 0 / 0 |
| SUM (`sum-best`) | 98.0% | 100 / 72 | 0 / 89 | 100 / 84 |
| Heuristic | 80.4% | 69 / 0 | 35 / 106 | 53 / 0 |

Raw, the non-identical pages are mostly code (`PAGE_EXECUTE_READ`) with absolute addresses relocated by ASLR (51.7% of the 32-bit pairs and 8.9% of the 64-bit pairs differ), and ssdeep and sdhash give 0 between them. With SUM, 33,992 non-identical pairs (2%) remain: medians ssdeep 72, TLSH 92 and sdhash 72 (sdhash comparable in 66%).

## `preservation_margin.py pages`: E3, per-page preservation margin

Sample stratified by architecture and operating system from the `sum-best` index. It rebuilds each
page from its ZIP, repeats the de-relocation and requires its SHA-256 to match E0 before
modifying it. The factorial design uses:

- positions inside a null run, inside a null run of an executable section
  (`code_cave`), uniform, and at the start of each quarter;
- `00`, `90`, `cc`, random bytes and the 16 B executable shellcode from the proof of concept;
- sizes 1, 4, 16, 64, 256, 512, 1024 and 2048 B;
- up to 200 distinct artifacts per cell (no resampling if fewer are eligible) and seed `20261028`.

A write that changes no byte is recorded as a *no-op*, but is excluded from all
success rates. Exact collision, saturation (ssdeep/sdhash 100 or TLSH 0) and acceptance
with E1's τ95 and τ99 are reported, with 95% Wilson confidence intervals. Each cell is a resumable
Parquet; `attempts.csv` counts valid attempts and `summary.csv` contains the results.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/modules-Windows:/data/modules-Windows:ro \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python preservation_margin.py pages \
    /data/modules-Windows /work/e0-sum-best /work/analysis/sum-best/e1_thresholds.csv \
    /work/analysis/e3-pages --workers 12"
```

Full run: 4250 pages from 17 strata, 51,820 attempts and 48,801 writes that
changed bytes. The 1600 `zero/zero` writes were correctly identified as *no-op*.
Result of the shellcode inside null runs; each cell uses 200 distinct pages. The cell
gives the percentage that passes τ95 and, in parentheses, the valid comparisons:

| Bytes | ssdeep | TLSH | sdhash |
|---:|---:|---:|---:|
| 1 | 13.5% (200) | 0% (188) | 29.8% (161) |
| 4 | 11.5% (200) | 0% (186) | 31.5% (149) |
| 16 | 4.5% (200) | 0% (186) | 34.8% (155) |
| 64 | 28.5% (200) | 0% (177) | 52.9% (136) |
| 256 | 31.0% (200) | 0% (157) | 77.6% (107) |
| 512 | 28.0% (200) | 0% (170) | 82.9% (111) |
| 1024 | 21.5% (200) | 0% (163) | 84.6% (91) |
| 2048 | 7.0% (200) | 0% (143) | 77.6% (49) |

With τ99, sdhash accepts 100% of the comparable mutants; TLSH falls from 99.5% with 1 B to
3.5% with 2048 B. Executable caves are scarce: there are 276 eligible pages up to 16 B,
93 for 64 B, 46 for 256 B, 16 for 512 B, 6 for 1024 B and 3 for 2048 B. They are not resampled.


## `optimized_attack.py`: E4, position and padding search

E4 uses the same stratified pool as E3 and keeps the payload fixed. For each page and size it
compares three attacker capabilities:

1. `baseline`: one deterministic position inside a null run;
2. `placement`: the best of up to 16 positions, without changing any additional byte;
3. `optimized`: the best combination of position and padding before or after the payload.

The padding takes at most 256 B and tries `90`, `cc`, random bytes and the counter
`00..ff`. The no-padding variant always takes part; ties are broken in favour of the one that changes the fewest
bytes. Optimization is done separately for ssdeep, TLSH and sdhash, with knowledge of the reference
digest. It is therefore an upper bound for an informed attacker, not a black-box attack.
Each cell uses up to 200 distinct pages, without replacement, and runs both on null runs
and on executable-section caves.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python optimized_attack.py \
    /work/analysis/e3-pages/pool.parquet /work/analysis/sum-best/e1_thresholds.csv \
    /work/analysis/e4-optimized --workers 12"
```

Full run: 1044 artifact-cell combinations and 3132 independent optimizations. The
table shows the rate that reaches τ95 as `baseline → placement → optimized`:

| Scope | Payload | Pages | ssdeep | sdhash |
|---|---:|---:|---:|---:|
| Null run | 16 B | 200 | 11.5 → 12.5 → 26.0% | 38.5 → 55.5 → 60.0% |
| Null run | 64 B | 200 | 24.0 → 32.5 → 35.0% | 44.0 → 53.5 → 53.5% |
| Null run | 256 B | 200 | 25.5 → 25.5 → 25.5% | 45.0 → 47.5 → 47.5% |
| Null run | 512 B | 200 | 23.5 → 23.5 → 23.5% | 43.5 → 47.5 → 48.0% |
| Executable cave | 16 B | 151 | 14.6 → 17.9 → 42.4% | 26.5 → 48.3 → 58.9% |
| Executable cave | 64 B | 67 | 37.3 → 40.3 → 40.3% | 37.3 → 56.7 → 58.2% |
| Executable cave | 256 B | 16 | 31.3 → 31.3 → 31.3% | 31.3 → 43.8 → 43.8% |
| Executable cave | 512 B | 10 | 20.0 → 20.0 → 20.0% | 30.0 → 40.0 → 40.0% |

TLSH does not reach τ95 (distance 0) on any of the 1044 pages, not even with the oracle.
Padding does reduce its distance and improves acceptance with τ99: in null runs it goes from 83.5 to
87.5% with 16 B, from 65.5 to 80.0% with 64 B, from 16.5 to 40.5% with 256 B and from 4.0 to 17.0% with
512 B. For sdhash almost all of the improvement comes from choosing the position; padding contributes mainly
with 16 B. For ssdeep, padding doubles the 16 B rate in executable caves (17.9→42.4%),
but stops contributing with payloads of 256 B or more.


## `mechanism_analysis.py`: E5, internal mechanism

Rebuilds each E4 winner and requires the recomputed scores to match the
stored ones. It then instruments:

- the cut points of the ssdeep rolling hash at the digest's two block sizes, following
  [`ssdeep` 2.14.1 `fuzzy.c`](https://github.com/ssdeep-project/ssdeep/blob/release-2.14.1/fuzzy.c);
- checksum, length value, quartile ratios and the 128 bucket codes of the TLSH digest,
  following the representation in [`tlsh_impl.h`](https://github.com/trendmicro/tlsh/blob/master/include/tlsh_impl.h);
- number of features and bits added, removed and shared in the Bloom filters serialized
  by sdhash 3.4. These are feature aggregates; the SDBF does not keep their original offsets.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python mechanism_analysis.py \
    /work/analysis/e3-pages/pool.parquet /work/analysis/e4-optimized \
    /work/analysis/e5-mechanisms 12"
```

The full run rebuilt 2421 distinct mutants and exactly validated the 8320
stage scores obtained from 589 pages. The `baseline → optimized` change is:

| Algorithm | Comparable pairs | Score improved | New τ95 successes | τ95 losses |
|---|---:|---:|---:|---:|
| ssdeep | 1044 | 341 | 95 | 0 |
| TLSH | 904 | 709 | 0 | 0 |
| sdhash | 646 | 207 | 142 | 0 |

The internal states explain different results for each algorithm:

- **ssdeep:** among the optimized winners that reach τ95, the median similarity of the
  digest strings is 0.962 and the Jaccard of second-block cut points is 1.000; among
  the failures they are 0.400 and 0.473. The digest block size changes in only 2/318 successes, but
  in 383/726 failures. Useful padding mainly preserves the segmentation of the second string.
- **TLSH:** the median distance drops from 64.5 to 35.5, but the minimum is still 1 and no
  mutant reproduces the exact digest required by τ95. The length does not change in any row. In
  the optimized ones, the distance correlates mostly with the difference in bucket
  codes (Spearman ρ=0.966 for its absolute difference), while the oracle reduces the medians
  of the Q1 and Q2 differences from 2 to 1. The checksum changes in 890/904 optimized ones; it is not enough to
  explain the limit because the remaining 14 do not reach distance 0 either.
- **sdhash:** the 557 optimized successes have score 100. Of them, 521 remove no
  Bloom bit of the original; the 89 failures remove at least one. The number of removed bits is
  the dominant internal signal (Spearman ρ=-0.810 with the score): the attack works when it
  adds features while losing almost none of those selected by the original.

The breakdown by scope, size, stage and outcome is in
[`results/e5_mechanism_summary.csv`](results/e5_mechanism_summary.csv).

### `tlsh_position.py`: why TLSH tolerates writes at the start of the page

In E3, writing 1 B at byte 0 preserves the TLSH digest in 70.7% of the pages, and in
any other quarter in none. The script reimplements the TLSH 4.7.2 state
(`fast_update` in `src/tlsh_impl.cpp`): each window `a[i-4..i]` with `i ≥ 4` adds six triplets
that contain `a[i]` and updates the checksum with `(a[i], a[i-1])`. It reproduces the 4112 TLSH digests
of the pool and the 2304 stored τ95 results of `q1`–`q4` with the 1, 4 and 16 B shellcode.
It then writes `0xB8` at fixed positions in every page of the pool. It runs in the container on
the experiment host; it was re-run there and produced byte-identical CSVs:

```bash
docker run --rm --cpus 4 --user "$(id -u):$(id -g)" -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python tlsh_position.py /work/analysis/e3-pages/pool.parquet \
    /work/analysis/e3-pages/trials /work/analysis/tlsh-position"
```

Saved output: `../artifacts/analysis/tlsh-position.out`.

| Position | Affected triplets | Identical digest | Checksum changes | Bucket codes intact |
|---:|---:|---:|---:|---:|
| 0 | 3 | 78.8% | 0% | 79.8% |
| 1 | 6 | 64.3% | 0% | 65.8% |
| 2 | 9 | 52.2% | 0% | 54.2% |
| 3 | 12 | 0% | 100% | 46.6% |
| 4–4091 | 18 | ≤ 0.24% | ≥ 99.4% | 32.9–35.5% |
| 4095 | 6 | 0% | 100% | 67.8% |

Bytes 0–2 do not enter the checksum and enter few triplets; from byte 3 on, any
change alters the checksum except by coincidence (≈ 1/256). The last byte also enters
few triplets, but it changes the checksum and no digest is preserved: the decisive condition is
avoiding the checksum. Results: [`results/tlsh_position_sweep.csv`](results/tlsh_position_sweep.csv)
and [`results/tlsh_quarter_mechanism.csv`](results/tlsh_quarter_mechanism.csv).

## `chain_attack.py`: E6, fragmented payload

Fragments a benign payload, chains it with 5-byte relative jumps and only scores the
memory dumped by Unicorn if execution reaches `int3` with the expected registers and has
visited every fragment. The thresholds are those of E1 with SUM. sdhash requires at least 16
features in both digests.

- `poc`: the three instructions of the PoC, one per page. The intermediate pages are
  overwritten in 10 B.
- `scale`: the split into 82 pages described in the paper, with 11 B slots plus the jump.
  It is not the SMBGhost exploit: it is a deterministic sum in `EAX`.

82 pages is only the naive split of the SMBGhost kernel shellcode (902 B / 11 B).
`smbghost_fragments.py` disassembles that shellcode (exploit-db 48537) with Capstone: 694 B of
x86-64 code and 208 B of RIP-relative addressed data. 41 of the 63 cuts every 11 B of the
code fall inside an instruction; respecting instruction boundaries the code needs at
least 74 fragments, and the data, without jumps, at least 13 more pages (≥ 87 in total). 26 relative
jumps (12 of them 8-bit) and 13 RIP-relative references would have to be rewritten.

The exploit is not redistributed. Download it from the official Exploit-DB GitLab mirror, verify
its SHA-256 and run the script in the container from the repository root:

```bash
curl -L -o 48537.py https://gitlab.com/exploit-database/exploitdb/-/raw/main/exploits/windows/remote/48537.py
echo '04961610ed79ae2bb702c4dff1662b7559b2c8bfb6f60dd89c2bb2d072e3e4b9  48537.py' | sha256sum -c
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/in:ro" -v "$PWD/analysis:/code" sda-preservation \
  python /code/smbghost_fragments.py /in/48537.py
```

Saved output: `../artifacts/analysis/smbghost-fragments.out`.

The positions are the null prefix at offset 0, as in the published PoC, and an executable
cave. A chain does not mix architectures. The median number of bytes actually changed is 5
in `poc` and 14 in `scale`.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python chain_attack.py \
    /work/analysis/e3-pages/pool.parquet /work/analysis/sum-best/e1_thresholds.csv \
    /work/analysis/e6-chains 12"
```

### Replication of the published PoC

`generate_exploit.py` and `emulate.py` reproduce the stored dumps byte for byte and end
with `EAX=1`, `EBX=2` and `ECX=3`. `poc_replication.py` scores the dumps with the E1 criterion
and locates the pages by SHA-256 in the E0 indexes. All three are in the corpus and the
guided de-relocation does not change them. The search stops at the first ZIP containing each
page:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/attack-simulation && python generate_exploit.py && python emulate.py && \
    cd /work/code/analysis && python poc_replication.py /work/code/attack-simulation/dmps \
    /work/e0 /work/e0-sum-best"
```

Saved output: `../artifacts/analysis/e6-poc-replication.out`.

| Page | Confirmed location | Bytes | ssdeep | TLSH | sdhash |
|---|---|---:|---:|---:|---|
| 1 | `wlanpref.dll`, Windows 7 32-bit, page 287 | 5 | 22 | 17 | 3 features, not comparable; identical digest |
| 2 | `accessibilitycpl.dll`, Server 2016 Datacenter 32-bit, page 391 | 5 | 99 | 5 | 34 features, score 100, identical digest |
| 3 | `WlanMM.dll`, Server 2016 Datacenter 32-bit, page 736 | 3 | 97 | 3 | 27 features, score 100, identical digest |

Digest equality reproduces the published result: identical sdhash on all three pages and
different TLSH/ssdeep. With the E1 criterion, page 1 is not a useful sdhash collision.
None reaches τ95 for ssdeep or TLSH. Pages 2 and 3 do reach τ95 and τ99 for sdhash, and
τ99 for the other two.

### Chains over the E3 pool

The 191 PoC chains and the 4 82-page chains finished emulation correctly.
A chain passes the threshold only if all its pages are comparable and pass it. The per-page
rate has the comparable pages as its denominator.

| Payload | Position | Chains | ssdeep τ95 | TLSH τ95 | sdhash τ95 |
|---|---|---:|---|---|---|
| PoC | Prefix | 99 | 0/297 · 0/99 | 0/223 · 0/99 | 167/167 · 12/99 |
| PoC | Cave | 92 | 25/276 · 0/92 | 0/272 · 0/92 | 59/250 · 2/92 |
| 82 pages | Prefix | 2 | 2/164 · 0/2 | 0/111 · 0/2 | 87/88 · 0/2 |
| 82 pages | Cave | 2 | 17/164 · 0/2 | 0/161 · 0/2 | 34/146 · 0/2 |

TLSH does not reach τ95 on any of the 901 executed pages. ssdeep does not preserve it in any
chain. In the prefix, the 87 PoC chains that do not pass sdhash τ95 fail because some
page has fewer than 16 features; the 12 chains in which all three pages are comparable
score 100. In caves, 68 of 92 fail because of a comparable score below τ95: writing
inside an executable section is not equivalent to writing over the PoC's null prefix.

With τ99 the three-page PoC does get through complete chains. In caves it is 80/92 for ssdeep,
85/92 for TLSH and 70/92 for sdhash; in the prefix, 39/99, 36/99 and 12/99. No 82-page
chain passes τ95 or τ99 for any algorithm.

The per-architecture breakdown is in
[`results/e6_chain_summary.csv`](results/e6_chain_summary.csv).

## `countermeasures.py`: E7, countermeasures and false positives

Evaluates the two countermeasures proposed in the paper with the artifacts already measured.

- **Acceptance policies.** The defender accepts a page if ssdeep, TLSH or sdhash passes
  its E1 threshold (`ssdeep`, `tlsh`, `sdhash`), if all three pass it (`all3`) or if
  two pass it (`majority`); `sha256` accepts only identical copies. A missing score (TLSH `-` or
  sdhash with fewer than 16 features) is ignored (`open`) or rejects the page (`closed`). The
  legitimate ones are the 1,710,855 E1 pairs with SUM, 33,992 of them non-identical. The attacks
  are the 10,364 E3 `shellcode` mutants and the 901 pages, 191 PoC chains and 4 82-page chains
  of E6. The thresholds come from those same legitimate pairs.
- **Byte rules**, written as YARA hex strings and evaluated with the
  equivalent regular expression: an `E9` jump followed by four zeros, an island of 1–16 bytes
  between two runs of 16 zeros, their union, and the exact signatures of each payload's fragments.
  False positives are counted on the 4250 unmodified pages of the E3 pool, in their
  SUM form and raw (as a memory scanner sees them, reread from the corpus ZIPs). The pool is
  stratified; the corpus rate weights each stratum by its pages in the E0 index with SUM.
  The E6 pages are regenerated with the E6 seeds; the script aborts if artifact, offset or
  execution result differ from what was stored.

```bash
docker run --rm --cpus 8 --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/modules-Windows:/data:ro -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python countermeasures.py \
    /work/analysis/e3-pages/pool.parquet /work/analysis/sum-best/e1_pairs.parquet \
    /work/analysis/e3-pages/trials /work/analysis/e6-chains/trials \
    /work/analysis/sum-best/e1_thresholds.csv /work/analysis/e7-countermeasures \
    /work/e0-sum-best /data"
```

With missing scores ignored:

| Threshold | Policy | Non-identical legitimate | E3 mutants | PoC chains |
|---|---|---:|---:|---:|
| — | `sha256` | 0/33,992 | 0/10,364 | 0/191 |
| τ95 | `sdhash` | 12,666 (37.3%) | 3375 (32.6%) | 105 (55.0%) |
| τ95 | `all3` | 2 (0.006%) | 3 (0.03%) | 0 |
| τ99 | `sdhash` | 18,620 (54.8%) | 10,289 (99.3%) | 191 (100%) |
| τ99 | `majority` | 18,131 (53.3%) | 8796 (84.9%) | 188 (98.4%) |
| τ99 | `all3` | 7725 (22.7%) | 5739 (55.4%) | 115 (60.2%) |

- With SUM and τ95, requiring all three algorithms is in practice equivalent to comparing SHA-256:
  it accepts 2 more non-identical legitimate pairs and lets through 3 E3 mutants and no chain.
- With τ99, cross-validation reduces attack acceptance compared with sdhash, but still lets
  through 115 of 191 PoC chains and accepts less than a quarter of the legitimate drift.
- Rejecting missing scores costs legitimate pairs without closing the attack: `all3` accepts
  only 90.1% (τ95) or 90.5% (τ99) of all legitimate pairs, and with τ99 still lets through
  80 PoC chains.
- The 82-page chains only pass with sdhash alone (1/4 with τ95 and 4/4 with τ99) or with
  majority and τ99 (2/4), ignoring missing scores.

| Rule | FP in the pool (SUM) | Raw FP, weighted | PoC pages detected | PoC chains detected |
|---|---:|---:|---:|---:|
| Jump to padding | 79/4250 (1.9%) | 1.9% | 338/573 | 188/191 |
| Island in null run | 370/4250 (8.7%) | 9.0% | 231/573 | 160/191 |
| Union of both | 411/4250 (9.7%) | 9.9% | 425/573 | 191/191 |
| PoC signature | 596/4250 (14.0%) | 14.0% | 573/573 | 191/191 |
| 82-page payload signature | 0/4250 | 0% | 0/573 | 0/191 |

The union of the generic rules detects every chain, and combined with `all3` and τ99 it lets
none through. The cost is 9.9% of legitimate pages flagged in memory, about 460,000 of
the 4,629,285 pages in the index. Whether the pages are raw or de-relocated barely changes the
rate. The exact PoC signature fails even more: its
`mov reg, imm32` instructions appear in 14% of the legitimate pages. The 82-page payload
signature has no false positives because its immediates are synthetic, and it requires knowing the
exact payload. The generic rules were evaluated against this payload, not against an attacker who
knows them.

Full tables: [`results/e7_policies.csv`](results/e7_policies.csv),
[`results/e7_rules.csv`](results/e7_rules.csv) and
[`results/e7_combined.csv`](results/e7_combined.csv).


## E8: generalization to full PE files

`pe_index.py` builds a reproducible index of the PE files from VMs 101–104 and 107. It only walks
`maquinaNNN/NNN{dll,dll64,exe,exe64,sys,sys64}`; it does not duplicate the full extraction of VM 107.
`pe_drift_baseline.py` pairs by architecture, type and unambiguous name in two families of
legitimate versions: Server 2012 R2→2016→2019 and Windows 7→Windows 10 21H2. Its thresholds are
specific to full files; E1's page thresholds are not reused.

`preservation_margin.py pe` applies the E3 protocol. In this mode a cave is a null run
inside the raw bytes of an executable section and the sizes are 16, 64, 256, 1024, 4096,
16384 and 65536 B. Arbitrary positions can break the PE: they measure the algorithm's margin
and do not by themselves constitute a functional attack. The `code_cave` cells are the variant that
preserves the structure.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/PE-Windows-system-files:/data/PE-Windows:ro \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && \
    python pe_index.py /data/PE-Windows /work/e8-pe-index 12 && \
    python pe_drift_baseline.py /work/e8-pe-index /work/analysis/e8-pe 12 && \
    python preservation_margin.py pe /data/PE-Windows /work/e8-pe-index \
      /work/analysis/e8-pe/e8_thresholds.csv /work/analysis/e8-pe/margin --workers 12"
```

The index contains 31,265 valid PE files. 30 16-bit compatibility NE files are excluded
(`compobj.dll`, `ole2*.dll`, `storage.dll` and `typelib.dll`, present in all five VMs). The
baseline contains 14,157 legitimate pairs, of which only 196 (1.4%) are identical:

| Algorithm | Median | τ95 | τ99 |
|---|---:|---:|---:|
| ssdeep | 0 | 0 | 0 |
| TLSH | 81 | 320 | 469.4 |
| sdhash | 3 | 0 | 0 |

Therefore, accepting full versions from different operating systems makes the ssdeep and sdhash
thresholds degenerate; a mutant passing those thresholds does not demonstrate preservation. For
E8, exact equality, saturation and TLSH distance are the informative measures.

The run uses 2509 PE files from 29 strata, with 43,350 attempts and 41,569 valid changes. Result
of the shellcode in executable-section caves:

| Bytes | Eligible PEs | PEs tested | ssdeep exact | TLSH median | sdhash 100 |
|---:|---:|---:|---:|---:|---:|
| 16 | 2416 | 200 | 1.0% | 1 | 63.5% |
| 64 | 2289 | 200 | 36.5% | 2 | 60.0% |
| 256 | 1511 | 200 | 98.5% | 5 | 54.5% |
| 1024 | 43 | 43 | 100% | 3 | 69.8% |
| 4096 | 7 | 7 | 100% | 3 | 57.1% |
| 16384 | 4 | 4 | 100% | 16 | 25.0% |
| 65536 | 1 | 1 | 100% | 6 | 100% |

The last three sizes are exploratory because of their low number of eligible PEs. The
65,536 B case is `maquina102/102sys/nvlddmkm.sys`: 28,672 bytes and the SHA-256 change, but ssdeep
keeps exactly the same digest and score 100.

Verification of the E8 scripts: re-running five full cells
(`code_cave/shellcode` with 16 and 65,536 B, `zero/random/1024`, `uniform/shellcode/4096` and
`q1/nop/256`, 801 rows) exactly reproduces the stored trials. Recomputing the index on
25 PEs from the pool and 300 drift pairs gives the same digests and scores. `sdhash-pairs`
matches `sdhash -g`, also on `sdbf-dd` digests (files larger than 16 MB, 44 in the
index). `sdhash_features` miscounted the features of `sdbf-dd`: it took the block size
as the number of elements of the last filter. This is fixed; for those 44 PEs the stored
`sdhash_features` column overestimates the value, which changes no result because they all
far exceed the required 16 features.

#### Where caves land when the PE is loaded

An E8 cave is a null run inside the raw bytes of an executable section. The
loader only maps `VirtualSize` bytes as section content, rounded up to
`SectionAlignment`. `pe_cave_mapping.py` classifies each write:

```bash
docker run --rm --cpus 4 --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/PE-Windows-system-files:/data/PE-Windows:ro \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && python pe_cave_mapping.py \
    /work/analysis/e8-pe/margin/trials /work/analysis/e8-pe/optimized/trials \
    /data/PE-Windows /work/analysis/e8-pe/cave-mapping"
```

Of the 655 shellcode writes into caves, 194 land inside `VirtualSize` and 461 (70%)
after it, although always within the last aligned page of the section. None lands outside
what is mapped. That page is executable, but we have not verified whether the loader copies the
bytes after `VirtualSize` from the file or zeroes them. To guarantee execution, the
attacker would have to enlarge `VirtualSize` in the section header, which changes bytes that
this experiment does not count.

The conclusions hold with only the writes inside `VirtualSize`: ssdeep exact in
13/27 with 64 B, 15/15 with 256 B and 31/31 with 1024 B; sdhash 100 in 66/109 with 16 B. In the
optimized attack on PEs, 153 TLSH winners are inside `VirtualSize` and 39 of them preserve the
exact digest (70 of 398 in the final page). Details:
[`results/e8_cave_mapping.csv`](results/e8_cave_mapping.csv) and
[`results/e4_pe_cave_mapping.csv`](results/e4_pe_cave_mapping.csv).

### Optimized attack on full PE files

`optimized_attack.py --mode pe` applies the E4 search (up to 16 positions and padding of
up to 256 B before or after the payload, 144 candidates per PE) to the E8 pool, with the E8
sizes. Candidates are written to disk as they are generated, so a large PE is not replicated
in memory. On pages, the refactored version exactly reproduces the stored E4 trials
(`code_cave` and `zero` with 16 B, 1053 rows). Since the E8 thresholds are degenerate,
exact digest and saturation are reported. `pe_optimized_check.py` rebuilds each winner with
exact TLSH and checks the mechanism.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/PE-Windows-system-files:/data/PE-Windows:ro \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && \
    python optimized_attack.py /work/analysis/e8-pe/margin/pool.parquet \
      /work/analysis/e8-pe/e8_thresholds.csv /work/analysis/e8-pe/optimized --mode pe \
      --root /data/PE-Windows --sizes 16,64,256,1024,4096,16384,65536 --workers 12 && \
    python pe_optimized_check.py /work/analysis/e8-pe/optimized \
      /work/analysis/e8-pe/margin/pool.parquet /data/PE-Windows"
```

Executable-section caves, `baseline → position → position+padding`. Requiring room for the
padding reduces the eligible PEs relative to E8 from 256 B on:

| Bytes | PEs | ssdeep exact | TLSH exact | sdhash 100 |
|---:|---:|---:|---:|---:|
| 16 | 200 | 3 → 6 → **42** | 2 → 9 → **43** | 134 → 182 → 193 |
| 64 | 200 | 78 → 99 → 106 | 0 → 1 → **33** | 135 → 177 → 183 |
| 256 | 103 | 103 → 103 → 103 | 0 → 0 → **25** | 76 → 82 → 82 |
| 1024 | 36 | 36 → 36 → 36 | 0 → 0 → 7 | 24 → 25 → 25 |
| 4096 | 7 | 7 → 7 → 7 | 0 → 1 → 1 | 4 → 4 → 4 |
| 16384 | 4 | 4 → 4 → 4 | 0 → 0 → 0 | 1 → 1 → 1 |
| 65536 | 1 | 1 → 1 → 1 | 0 → 0 → 0 | 1 → 1 → 1 |

- **TLSH can be preserved exactly in a full PE**, unlike the E4
  pages. In null runs the oracle achieves it in 44/200 PEs with 16 B, 37/200 with 64 B, 24/200 with
  256 B, 22/200 with 1024 B and 12/147 with 4096 B. Those runs may be in headers or overlay:
  they measure the algorithm's margin and do not guarantee a functional PE; the caves in the table do
  preserve the structure. The 249 winners with exact TLSH were rebuilt and verified:
  the SHA-256 changes, the digest does not. Between 7 and 7423 bytes change, with median 92. Example:
  `maquina101/101dll/mydocs.dll`, 16 B in a cave with trailing `nop` padding, 23 bytes
  changed.
- **The mechanism is the one-byte checksum.** In a large file, the TLSH quartiles
  absorb a small change: of the 628 `baseline` mutants at distance 1, 627 differ from the
  original only in the checksum. Trying positions and paddings acts as a search over that
  byte. Every padding family produces exact winners: 73 counter, 69 `nop`,
  54 random, 38 `int3` and 15 without padding.
- **ssdeep:** padding brings the exact digest from 3 to 42 PEs with 16 B in caves, and from 35 to 124
  in null runs. From 256 B on it was already exact without optimization.
- **sdhash:** position raises score 100 from 134 to 182 PEs with 16 B. Its exact digest is almost
  never preserved, at most 15 PEs per cell.

Details: [`results/e8_pe_optimized_summary.csv`](results/e8_pe_optimized_summary.csv),
[`results/e8_pe_optimized_exact_counts.csv`](results/e8_pe_optimized_exact_counts.csv) and
[`results/e8_pe_optimized_padding_choices.csv`](results/e8_pe_optimized_padding_choices.csv).

### Functions

`function_analysis.py` uses Zineb's radare2 JSON files (28,297 files). The address in the
JSON is virtual; the file offset is derived from the PE. These JSON files store at most 500 B of
each function. Up to 500 B only contiguous functions are used: full body, identical to the file.
Above that, the digest is computed over the file range `[offset, offset+size)` if the
500 stored bytes match its start and the range does not exceed 8192 B. radare also returns
ranges of up to 12.6 MB that are not a function; they are excluded as implausible. sdhash 3.4 does not
emit a digest below 512 B.

```bash
docker run --rm --cpus 12 --user "$(id -u):$(id -g)" \
  -v /mnt/HOME_VIEJOS/zhelali/archivos:/j:ro \
  -v /mnt/DATASETS/PE-Windows-system-files:/pe:ro \
  -v /var/tmp/sda-work:/work sda-preservation \
  sh -c "cd /work/code/analysis && \
    python function_analysis.py index /j /pe /work/analysis/e8-pe/margin/pool.parquet \
      /work/analysis/functions 12 && \
    python function_analysis.py overlap /work/analysis/e8-pe/margin/pool.parquet \
      /work/analysis/e8-pe/margin/trials /work/analysis/functions && \
    python function_analysis.py drift /work/analysis/functions /pe 8 && \
    python function_analysis.py preserve /work/analysis/functions /pe 8"
```

28,221 JSON files were indexed. The PE was missing for 46 and 30 gave an error. The PEs of the E8 pool contain
984,748 function ranges. The whole corpus has 482,771 functions with a `sym.` symbol and a
contiguous body of at least 50 B; 476,891 carry the module prefix.

The E8 caves fall outside functions:

| Ranges considered | Executable null runs inside a function | Cave bytes | `shellcode` writes into caves |
|---|---:|---:|---:|
| All, including implausible ones | 26,876/108,891 (24.7%) | 30.0% | 114/631 |
| Plausible (≤ 8192 B) | 1010/108,887 (0.9%) | 2.9% | 36/630 (5.7%) |
| Contiguous | 305/108,865 (0.3%) | 1.3% | 1/629 |

The first row is an artifact of the implausible ranges. A defender who only hashes functions
misses at least 94% of the E8 writes into caves.

The drift of the same symbol-named function, with the E8 transitions, gives 108,400 pairs,
16,845 identical (15.5%). The ssdeep median is 0 and its thresholds degenerate to 0, as for the full
PE. TLSH has median 139, τ95 293 and τ99 340. These functions are at most 500 B,
so sdhash is not comparable in this drift.

Forcing 16 B of shellcode inside the function, 200 functions per architecture and size band:

| Band | Position | ssdeep median | TLSH median | sdhash 100 | sdhash exact |
|---|---|---:|---:|---:|---:|
| 50–255 B | start | 45 | 48 | — | — |
| 50–255 B | interior | 44.5 | 55 | — | — |
| 256–500 B | start | 94 | 25 | — | — |
| 256–500 B | interior | 93 | 31 | — | — |
| 512–8192 B | start | 96 | 17 | 156/156 | 143/156 |
| 512–8192 B | interior | 96 | 20 | 35/154 | 15/154 |

- With the function drift thresholds, **all** mutants pass τ95 for ssdeep (threshold 0)
  and TLSH (threshold 293). As in E8, the defender cannot accept different versions of the
  same function with a useful threshold.
- The exact ssdeep digest is preserved in 1 of 2400 mutants and the TLSH one in none.
- In functions of at least 512 B, writing at the start preserves sdhash score 100 in
  all comparable ones and its exact digest in 143 of 156. In the interior it drops to 35 and 15.
- The drift thresholds come from 50–500 B functions and are also applied to the
  512–8192 B band, for which there are no verified drift pairs.

Tables: [`results/function_overlap.csv`](results/function_overlap.csv),
[`results/function_drift_thresholds.csv`](results/function_drift_thresholds.csv) and
[`results/function_preserve.csv`](results/function_preserve.csv).

The aggregate tables of E3, E4, E5, E6, E7 and E8 and the 30 errors of the PE index are copied in `results/`.
The full outputs, including the parquet files, are in `../artifacts/`.
