"""E6: fragmented executable payload, emulated and scored against E1 thresholds.

Two payloads, both benign and checked by execution rather than by byte identity alone:

- poc: the paper's three x86 instructions, one fragment per page, with a 5-byte
  relative jump between pages. Intermediate pages are overwritten in 10 bytes.
- scale: the paper's 82-page fragmentation arithmetic (11 payload bytes plus a
  5-byte jump). The bytes are a deterministic add-eax stream, not an exploit;
  the emulator must visit every fragment and finish with the independently
  computed EAX.

Placements are the paper's leading-zero prefix and an executable code cave.
A chain never mixes architectures: 32-bit pages run in 32-bit mode and 64-bit
pages in 64-bit mode. Digests are computed on the memory dumped from the
emulator. sdhash scores require at least 16 features on both sides, the same
comparability rule as E1-E5.

Usage: python chain_attack.py POOL THRESHOLDS OUT [WORKERS] [CHAIN_LIMIT]
"""
import math
import os
import sys
import tempfile

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep
from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_32, UC_MODE_64, UcError
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX

from preservation_margin import load_thresholds, stable_rng, wilson
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
BASE = 0x100000
JUMP = 5
SEED = 20261029
PLACEMENTS = ("prefix", "code_cave")


def add_eax(immediate, six_byte):
    immediate &= 0xFFFFFFFF
    encoded = immediate.to_bytes(4, "little")
    return (b"\x81\xC0" if six_byte else b"\x05") + encoded


def scale_fragments(pages=82):
    """82 fragments of 11 bytes, matching the paper's split, ending in int3."""
    fragments = []
    eax = 0
    immediate_index = 1
    for page in range(pages):
        chunk = b""
        for six_byte in (True, False):
            immediate = (0x9E3779B9 * immediate_index) & 0xFFFFFFFF
            immediate_index += 1
            chunk += add_eax(immediate, six_byte)
            eax = (eax + immediate) & 0xFFFFFFFF
        if page == pages - 1:
            chunk += b"\xCC"
        fragments.append(chunk)
    return fragments, {"eax": eax, "ebx": 0, "ecx": 0}


PAYLOADS = {
    "poc": {
        "fragments": [
            b"\xB8\x01\x00\x00\x00",
            b"\xBB\x02\x00\x00\x00",
            b"\xB9\x03\x00\x00\x00\xCC",
        ],
        "expected": {"eax": 1, "ebx": 2, "ecx": 3},
        "budget": 10,
    },
    "scale": {
        "fragments": None,
        "expected": None,
        "budget": 16,
    },
}
PAYLOADS["scale"]["fragments"], PAYLOADS["scale"]["expected"] = scale_fragments()


def build_jmp(source, destination):
    relative = destination - (source + JUMP)
    return b"\xE9" + int(relative).to_bytes(4, "little", signed=True)


def write_size(fragment, last):
    return len(fragment) if last else len(fragment) + JUMP


def eligible(pool, placement, budget):
    if placement == "prefix":
        return pool[pool.data.map(lambda data: bytes(data[:budget]) == bytes(budget))]
    return pool[pool.cave_lengths.map(lambda lengths: len(lengths) > 0 and max(lengths) >= budget)]


def choose_offset(record, placement, budget, rng):
    if placement == "prefix":
        return 0
    runs = [
        (int(start), int(length))
        for start, length in zip(record.cave_starts, record.cave_lengths)
        if int(length) >= budget and int(start) + budget <= PAGE
    ]
    start, length = runs[int(rng.integers(len(runs)))]
    return start + int(rng.integers(length - budget + 1))


def assemble(group, length, seed, label, limit):
    rng = stable_rng(seed, label)
    order = rng.permutation(len(group))
    ordered = group.iloc[order].reset_index(drop=True)
    chains = [
        ordered.iloc[start:start + length]
        for start in range(0, len(ordered) - length + 1, length)
    ]
    return chains[:limit] if limit else chains




def run_emulation(records, fragments, offsets, architecture, expected):
    mode = UC_MODE_32 if architecture == "32-bits" else UC_MODE_64
    emulator = Uc(UC_ARCH_X86, mode)
    mutated, starts = [], []
    for index, record in enumerate(records.itertuples(index=False)):
        address = BASE + index * PAGE
        fragment = fragments[index]
        offset = offsets[index]
        jump = b""
        if index + 1 < len(fragments):
            jump = build_jmp(
                address + offset + len(fragment),
                BASE + (index + 1) * PAGE + offsets[index + 1],
            )
        data = bytearray(bytes(record.data))
        end = offset + len(fragment) + len(jump)
        if end > PAGE:
            raise RuntimeError(f"La escritura desborda la página en offset {offset}")
        data[offset:offset + len(fragment)] = fragment
        if jump:
            data[offset + len(fragment):end] = jump
        mutated.append(bytes(data))
        starts.append(address + offset)
        emulator.mem_map(address, PAGE)
        emulator.mem_write(address, mutated[-1])

    state = {"int3": False, "eax": None, "ebx": None, "ecx": None}
    visited = set()

    def on_interrupt(uc, interrupt, _):
        if interrupt == 3:
            state.update({
                "int3": True,
                "eax": uc.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF,
                "ebx": uc.reg_read(UC_X86_REG_EBX) & 0xFFFFFFFF,
                "ecx": uc.reg_read(UC_X86_REG_ECX) & 0xFFFFFFFF,
            })
            uc.emu_stop()

    def on_code(_uc, address, _size, _):
        visited.add(address)

    emulator.hook_add(UC_HOOK_INTR, on_interrupt)
    emulator.hook_add(UC_HOOK_CODE, on_code)
    try:
        emulator.emu_start(starts[0], 0, timeout=2_000_000, count=max(64, 8 * len(fragments)))
    except UcError:
        pass
    dumped = [bytes(emulator.mem_read(BASE + index * PAGE, PAGE)) for index in range(len(fragments))]
    functional = (
        state["int3"]
        and dumped == mutated
        and all(start in visited for start in starts)
        and state["eax"] == expected["eax"]
        and state["ebx"] == expected["ebx"]
        and state["ecx"] == expected["ecx"]
    )
    return mutated, functional, state


def score_rows(rows, workers, thresholds):
    for row in rows:
        mutant = row.get("_mutant")
        if row["changed_bytes"] == 0 or mutant is None:
            continue
        row["mutant_tlsh"] = tlsh_digest(mutant)
        row["mutant_ssdeep"] = ssdeep.hash(mutant)
    with tempfile.TemporaryDirectory() as temporary:
        paths, indexes = [], []
        for index, row in enumerate(rows):
            mutant = row.pop("_mutant", None)
            if mutant is None or row["changed_bytes"] == 0:
                continue
            path = os.path.join(temporary, f"{index:06d}")
            with open(path, "wb") as handle:
                handle.write(mutant)
            paths.append(path)
            indexes.append(index)
        for index, digest in zip(indexes, sdhash_files(paths, workers)):
            rows[index]["mutant_sdhash"] = digest
            rows[index]["mutant_sdhash_features"] = sdhash_features(digest)
        pairs, pair_indexes = [], []
        for index in indexes:
            row = rows[index]
            if (
                row["original_sdhash_features"] >= MIN_SDHASH_FEATURES
                and row["mutant_sdhash_features"] >= MIN_SDHASH_FEATURES
            ):
                pairs.append(f"{full_sdbf(row['original_sdhash'])}\t{full_sdbf(row['mutant_sdhash'])}")
                pair_indexes.append(index)
        for index, score in zip(pair_indexes, sdhash_scores(pairs, workers)):
            rows[index]["sdhash_score"] = score
    for row in rows:
        if row["changed_bytes"] == 0:
            continue
        row["ssdeep_score"] = ssdeep.compare(row["original_ssdeep"], row["mutant_ssdeep"])
        row["tlsh_dist"] = tlsh_distance(row["original_tlsh"], row["mutant_tlsh"])
        row["sdhash_comparable"] = "sdhash_score" in row
        for algorithm, score_key, digest_key in (
            ("ssdeep", "ssdeep_score", "ssdeep"),
            ("tlsh", "tlsh_dist", "tlsh"),
            ("sdhash", "sdhash_score", "sdhash"),
        ):
            value = row.get(score_key)
            comparable = value is not None
            row[f"{algorithm}_exact"] = (
                row.get(f"original_{digest_key}") == row.get(f"mutant_{digest_key}") if comparable else None
            )
            row[f"{algorithm}_tau95"] = threshold_pass(algorithm, value, thresholds, 95)
            row[f"{algorithm}_tau99"] = threshold_pass(algorithm, value, thresholds, 99)
    return rows


def threshold_pass(algorithm, value, thresholds, acceptance):
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    limit = thresholds[algorithm][acceptance]
    return bool(value <= limit) if algorithm == "tlsh" else bool(value >= limit)


def chains(pool, payload_name, placement, limit=0, verbose=False):
    """Yield every E6 chain with its emulated pages, in the order and with the seeds of E6."""
    spec = PAYLOADS[payload_name]
    fragments = spec["fragments"]
    budget = spec["budget"]
    selected = eligible(pool, placement, budget)
    for architecture, group in selected.groupby("architecture", sort=True):
        built = assemble(group, len(fragments), SEED, f"{payload_name}|{placement}|{architecture}", limit)
        if verbose:
            print(
                f"{payload_name} {placement} {architecture}: elegibles {len(group)}, cadenas {len(built)}",
                flush=True,
            )
        for chain_id, records in enumerate(built):
            rng = stable_rng(SEED, payload_name, placement, architecture, chain_id)
            offsets = [choose_offset(record, placement, budget, rng) for record in records.itertuples(index=False)]
            mutated, functional, state = run_emulation(
                records, fragments, offsets, architecture, spec["expected"]
            )
            yield architecture, len(group), chain_id, records, offsets, mutated, functional, state


def cell_rows(pool, payload_name, placement, workers, thresholds, limit):
    spec = PAYLOADS[payload_name]
    fragments = spec["fragments"]
    budget = spec["budget"]
    rows = []
    for architecture, eligible_pages, chain_id, records, offsets, mutated, functional, state in chains(
        pool, payload_name, placement, limit, verbose=True
    ):
        for page_index, record in enumerate(records.itertuples(index=False)):
            original = bytes(record.data)
            mutant = mutated[page_index]
            rows.append({
                "payload": payload_name,
                "placement": placement,
                "architecture": architecture,
                "chain_id": chain_id,
                "page_in_chain": page_index,
                "artifact_id": record.artifact_id,
                "stratum": record.stratum,
                "offset": offsets[page_index],
                "budget": budget,
                "write_size": write_size(fragments[page_index], page_index == len(fragments) - 1),
                "changed_bytes": sum(left != right for left, right in zip(original, mutant)),
                "functional": functional,
                "observed_eax": state["eax"],
                "observed_ebx": state["ebx"],
                "observed_ecx": state["ecx"],
                "eligible_pages": eligible_pages,
                "original_tlsh": record.tlsh,
                "original_ssdeep": record.ssdeep,
                "original_sdhash": record.sdhash,
                "original_sdhash_features": int(record.sdhash_features),
                "_mutant": mutant,
            })
    if rows:
        score_rows(rows, workers, thresholds)
    return rows


OUTPUT_COLUMNS = [
    "payload", "placement", "architecture", "chain_id", "page_in_chain", "artifact_id", "stratum",
    "offset", "budget", "write_size", "changed_bytes", "functional", "observed_eax", "observed_ebx",
    "observed_ecx", "eligible_pages", "original_sdhash_features", "mutant_sdhash_features",
    "ssdeep_score", "tlsh_dist", "sdhash_score", "sdhash_comparable",
    "ssdeep_exact", "tlsh_exact", "sdhash_exact",
    "ssdeep_tau95", "ssdeep_tau99", "tlsh_tau95", "tlsh_tau99", "sdhash_tau95", "sdhash_tau99",
]


def summarize(frame):
    rows = []
    keys = ["payload", "placement", "architecture"]
    for key, group in frame.groupby(keys, sort=True):
        functional = group[group.functional]
        chain_groups = list(functional.groupby("chain_id")) if len(functional) else []
        for algorithm, score_column in (("ssdeep", "ssdeep_score"), ("tlsh", "tlsh_dist"), ("sdhash", "sdhash_score")):
            comparable = functional[functional[score_column].notna()]
            passed = comparable[f"{algorithm}_tau95"].dropna().astype(bool) if len(comparable) else pd.Series(dtype=bool)
            rate, low, high = wilson(int(passed.sum()) if len(passed) else 0, len(comparable))
            chain_pass95 = chain_pass99 = blocked = score_fail = 0
            for _chain_id, chain in chain_groups:
                values95 = chain[f"{algorithm}_tau95"]
                values99 = chain[f"{algorithm}_tau99"]
                if not values95.notna().all():
                    blocked += 1
                elif not values95.astype(bool).all():
                    score_fail += 1
                else:
                    chain_pass95 += 1
                chain_pass99 += int(values99.notna().all() and values99.astype(bool).all())
            chain_rate, chain_low, chain_high = wilson(chain_pass95, len(chain_groups))
            rows.append({
                "payload": key[0], "placement": key[1], "architecture": key[2], "algorithm": algorithm,
                "eligible_pages": int(group.eligible_pages.iloc[0]),
                "chains": group.chain_id.nunique(),
                "functional_chains": len(chain_groups),
                "pages": len(functional),
                "comparable": len(comparable),
                "median_score": comparable[score_column].median() if len(comparable) else math.nan,
                "page_tau95_%": rate, "page_tau95_ci_low": low, "page_tau95_ci_high": high,
                "page_tau99_%": wilson(int(comparable[f"{algorithm}_tau99"].dropna().astype(bool).sum()) if len(comparable) else 0, len(comparable))[0],
                "page_exact_%": wilson(int(comparable[f"{algorithm}_exact"].dropna().astype(bool).sum()) if len(comparable) else 0, len(comparable))[0],
                "chain_tau95": chain_pass95,
                "chain_blocked_incomparable": blocked,
                "chain_score_fail": score_fail,
                "chain_tau95_%": chain_rate, "chain_tau95_ci_low": chain_low, "chain_tau95_ci_high": chain_high,
                "chain_tau99": chain_pass99,
                "chain_tau99_%": wilson(chain_pass99, len(chain_groups))[0],
            })
    return pd.DataFrame(rows)


def main():
    pool_path, thresholds_path, out = sys.argv[1:4]
    workers = int(sys.argv[4]) if len(sys.argv) > 4 else max(1, os.cpu_count() // 2)
    limit = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    os.makedirs(os.path.join(out, "trials"), exist_ok=True)
    pool = pq.read_table(pool_path).to_pandas()
    thresholds = load_thresholds(thresholds_path)
    for payload_name in ("poc", "scale"):
        for placement in PLACEMENTS:
            shard = os.path.join(out, "trials", f"{payload_name}__{placement}.parquet")
            if os.path.exists(shard):
                print(f"existente {shard}", flush=True)
                continue
            rows = cell_rows(pool, payload_name, placement, workers, thresholds, limit)
            output = [{column: row.get(column) for column in OUTPUT_COLUMNS} for row in rows]
            temporary = shard + ".part"
            pq.write_table(pa.Table.from_pylist(output), temporary, compression="zstd")
            os.replace(temporary, shard)
    paths = [
        os.path.join(out, "trials", name)
        for name in sorted(os.listdir(os.path.join(out, "trials")))
        if name.endswith(".parquet")
    ]
    frame = pa.concat_tables([pq.read_table(path) for path in paths], promote_options="permissive").to_pandas()
    summary = summarize(frame)
    summary.to_csv(os.path.join(out, "summary.csv"), index=False)
    shown = summary[["payload", "placement", "architecture", "algorithm", "functional_chains", "pages", "comparable", "page_tau95_%", "chain_tau95_%"]]
    print(shown.to_string(index=False), flush=True)


if __name__ == "__main__":
    main()
