"""E7: countermeasures and false positives.

A. SDA acceptance policies. Legitimate pairs are the E1 SUM pairs (same module and build in
   Standard and Datacenter); attacks are the changed E3 mutants and the functional E6 pages.
   All three scores are available for every row, so cross-algorithm policies are evaluated on
   the same artefacts. A missing score (TLSH "-" or sdhash below 16 features) is handled
   fail-open (ignored, i.e. accepted) or fail-closed (rejected).
B. Byte-pattern rules, written as YARA hex strings and evaluated with the equivalent regular
   expressions. False positives are counted on the unmodified E3 pool pages, both SUM-derelocated
   and raw (as a memory scanner sees them, read back from the corpus ZIPs). The pool is
   stratified, so the corpus-level rate weights each stratum by its page count in the E0 SUM
   index. Detections are counted on the E6 pages, regenerated with the E6 seeds and checked
   against the stored E6 rows.

Usage: python countermeasures.py POOL E1_PAIRS E3_TRIALS E6_TRIALS THRESHOLDS OUT E0_SUM_INDEX CORPUS
"""
import glob
import os
import re
import sys
import zipfile

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from chain_attack import PAYLOADS, PLACEMENTS, chains
from preservation_margin import load_thresholds, wilson

ALGORITHMS = ("ssdeep", "tlsh", "sdhash")
SCORE = {"ssdeep": "ssdeep_score", "tlsh": "tlsh_dist", "sdhash": "sdhash_score"}
PAGE = 4096

RULES = {
    "trampoline_into_padding": (
        "{ E9 ?? ?? ?? ?? 00 00 00 00 }",
        re.compile(rb"\xE9[\x00-\xFF]{4}\x00{4}", re.DOTALL),
    ),
    "code_island_in_zero_run": (
        "{ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [1-16] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }"
        " (first byte after the leading run non-zero)",
        re.compile(rb"\x00{16}[\x01-\xFF][\x00-\xFF]{0,15}?\x00{16}", re.DOTALL),
    ),
}


def passes(frame, algorithm, thresholds, level):
    values = frame[SCORE[algorithm]]
    limit = thresholds[algorithm][level]
    passed = values <= limit if algorithm == "tlsh" else values >= limit
    return passed.astype(float).where(values.notna())


def decide(frame, policy, thresholds, level, missing):
    """Boolean acceptance per row; missing is 'open' or 'closed'."""
    if policy == "sha256":
        if "identical" in frame:
            return frame["identical"].astype(bool)
        return pd.Series(False, index=frame.index)
    fill = 1.0 if missing == "open" else 0.0
    votes = {
        algorithm: passes(frame, algorithm, thresholds, level).fillna(fill).astype(bool)
        for algorithm in ALGORITHMS
    }
    if policy in ALGORITHMS:
        return votes[policy]
    if policy == "all3":
        return votes["ssdeep"] & votes["tlsh"] & votes["sdhash"]
    if policy == "majority":
        return (votes["ssdeep"].astype(int) + votes["tlsh"].astype(int) + votes["sdhash"].astype(int)) >= 2
    raise ValueError(policy)


def rate_row(name, accepted):
    count = len(accepted)
    hits = int(accepted.sum())
    rate, low, high = wilson(hits, count)
    return {f"{name}_n": count, f"{name}_accepted": hits, f"{name}_%": rate, f"{name}_ci_low": low, f"{name}_ci_high": high}


def policy_table(legit, attack_sets, chain_frame, thresholds):
    rows = []
    policies = ("sha256",) + ALGORITHMS + ("all3", "majority")
    for level in (95, 99):
        for missing in ("open", "closed"):
            for policy in policies:
                row = {"level": level, "missing": missing, "policy": policy}
                accepted = decide(legit, policy, thresholds, level, missing)
                row.update(rate_row("legit_all", accepted))
                row.update(rate_row("legit_nonidentical", accepted[~legit.identical.to_numpy()]))
                for name, frame in attack_sets.items():
                    row.update(rate_row(name, decide(frame, policy, thresholds, level, missing)))
                chain_accept = (
                    chain_frame.assign(_ok=decide(chain_frame, policy, thresholds, level, missing).to_numpy())
                    .groupby(["payload", "placement", "architecture", "chain_id"])._ok.all()
                )
                for payload, group in chain_accept.groupby(level=0):
                    row.update(rate_row(f"e6_{payload}_chain", group))
                rows.append(row)
    return pd.DataFrame(rows)


def signature_rule(payload):
    fragments = PAYLOADS[payload]["fragments"]
    yara = " ".join(f"$f{i} = {{ {fragment.hex(' ').upper()} }}" for i, fragment in enumerate(fragments))
    pattern = re.compile(b"|".join(re.escape(fragment) for fragment in fragments), re.DOTALL)
    return yara + " condition: any of them", pattern


def regenerate_e6(pool, stored):
    pages = []
    for payload in PAYLOADS:
        for placement in PLACEMENTS:
            for architecture, _eligible, chain_id, records, offsets, mutated, functional, _state in chains(
                pool, payload, placement
            ):
                for index, record in enumerate(records.itertuples(index=False)):
                    pages.append({
                        "payload": payload, "placement": placement, "architecture": architecture,
                        "chain_id": chain_id, "page_in_chain": index, "artifact_id": record.artifact_id,
                        "offset": offsets[index], "functional": functional, "data": mutated[index],
                    })
    frame = pd.DataFrame(pages)
    keys = ["payload", "placement", "architecture", "chain_id", "page_in_chain"]
    joined = frame.merge(stored, on=keys, suffixes=("", "_stored"), validate="one_to_one")
    mismatch = (
        (joined.artifact_id != joined.artifact_id_stored)
        | (joined.offset != joined.offset_stored)
        | (joined.functional != joined.functional_stored)
    )
    if mismatch.any() or len(joined) != len(frame) or len(joined) != len(stored):
        raise RuntimeError(f"E6 regenerado no coincide con lo almacenado: {int(mismatch.sum())} filas")
    return joined


def stratum_pages(e0_index):
    """Pages per arch|os stratum, with the filters used to build the E3 pool."""
    counts = {}
    for path in sorted(glob.glob(os.path.join(e0_index, "shards", "*.parquet"))):
        frame = pq.read_table(path, columns=["zip", "arch_dir", "os_dir", "dereloc"]).to_pandas()
        frame = frame[~frame.zip.str.contains(r"\(1\)", regex=True) & frame.dereloc.isin(["guide", "linear"])]
        for (arch, system), count in frame.groupby(["arch_dir", "os_dir"]).size().items():
            counts[f"{arch}|{system}"] = counts.get(f"{arch}|{system}", 0) + int(count)
    return counts


def raw_pages(pool, corpus):
    pages = {}
    for zip_name, group in pool.groupby("path"):
        with zipfile.ZipFile(os.path.join(corpus, zip_name)) as archive:
            joined = archive.read("joinedModuleContents.dmp")
        for record in group.itertuples(index=False):
            start = int(record.page_index) * PAGE
            pages[record.artifact_id] = joined[start:start + PAGE]
    return [pages[key] for key in pool.artifact_id]


def weighted_rate(strata, hits, counts):
    per = pd.DataFrame({"stratum": strata, "hit": hits}).groupby("stratum").hit.mean()
    total = sum(counts[stratum] for stratum in per.index)
    return 100 * sum(per[stratum] * counts[stratum] for stratum in per.index) / total, total


def rule_table(pool, e6, counts, raw):
    rules = dict(RULES)
    for payload in PAYLOADS:
        rules[f"signature_{payload}"] = signature_rule(payload)
    generic = [pattern.pattern for _yara, pattern in RULES.values()]
    rules["either_generic"] = (
        " or ".join(RULES), re.compile(b"|".join(generic), re.DOTALL),
    )
    rows = []
    legit_pages = [bytes(data) for data in pool.data]
    for name, (yara, pattern) in rules.items():
        legit_hits = np.array([pattern.search(page) is not None for page in legit_pages])
        raw_hits = np.array([pattern.search(page) is not None for page in raw])
        row = {"rule": name, "yara": yara}
        row.update(rate_row("legit_page_fp", pd.Series(legit_hits)))
        row.update(rate_row("raw_page_fp", pd.Series(raw_hits)))
        row["legit_page_fp_weighted_%"], corpus_pages = weighted_rate(pool.stratum, legit_hits, counts)
        row["raw_page_fp_weighted_%"], _ = weighted_rate(pool.stratum, raw_hits, counts)
        row["corpus_pages"] = corpus_pages
        row["expected_fp_pages_in_corpus"] = row["raw_page_fp_weighted_%"] / 100 * corpus_pages
        hits = e6.data.map(lambda page, pattern=pattern: pattern.search(page) is not None)
        for (payload, placement), group in e6.assign(_hit=hits).groupby(["payload", "placement"]):
            row.update(rate_row(f"e6_{payload}_{placement}_page", group._hit))
            chain_hit = group.groupby(["architecture", "chain_id"])._hit.any()
            row.update(rate_row(f"e6_{payload}_{placement}_chain", chain_hit))
        rows.append(row)
    return pd.DataFrame(rows), rules


def combined_table(e6, rules, thresholds):
    rows = []
    for level in (95, 99):
        for missing in ("open", "closed"):
            accepted = decide(e6, "all3", thresholds, level, missing)
            for name in ("none", "trampoline_into_padding", "code_island_in_zero_run", "either_generic"):
                if name == "none":
                    flagged = pd.Series(False, index=e6.index)
                else:
                    flagged = e6.data.map(lambda page, pattern=rules[name][1]: pattern.search(page) is not None)
                evaded = accepted & ~flagged.astype(bool)
                frame = e6.assign(_ok=evaded.to_numpy())
                row = {"level": level, "missing": missing, "sda_policy": "all3", "rule": name}
                for (payload, placement), group in frame.groupby(["payload", "placement"]):
                    row.update(rate_row(f"e6_{payload}_{placement}_page", group._ok))
                    row.update(rate_row(
                        f"e6_{payload}_{placement}_chain", group.groupby(["architecture", "chain_id"])._ok.all()
                    ))
                rows.append(row)
    return pd.DataFrame(rows)


def main():
    pool_path, e1_path, e3_dir, e6_dir, thresholds_path, out, e0_index, corpus = sys.argv[1:9]
    os.makedirs(out, exist_ok=True)
    thresholds = load_thresholds(thresholds_path)
    pool = pq.read_table(pool_path).to_pandas()
    legit = pd.read_parquet(e1_path)
    e3 = pd.read_parquet(e3_dir)
    e3 = e3[(e3.attempted == True) & (e3.changed == True)]  # noqa: E712
    e6_stored = pd.read_parquet(e6_dir)
    e6_stored = e6_stored[e6_stored.functional]
    attack_sets = {
        "e3_all": e3,
        "e3_shellcode": e3[e3.content == "shellcode"],
        "e6_pages": e6_stored,
    }
    policies = policy_table(legit, attack_sets, e6_stored, thresholds)
    policies.to_csv(os.path.join(out, "policies.csv"), index=False)

    e6 = regenerate_e6(pool, e6_stored)
    print(f"E6 regenerado: {len(e6)} páginas, idénticas en artefacto, offset y ejecución", flush=True)
    rules_frame, rules = rule_table(pool, e6, stratum_pages(e0_index), raw_pages(pool, corpus))
    rules_frame.to_csv(os.path.join(out, "rules.csv"), index=False)
    combined = combined_table(e6, rules, thresholds)
    combined.to_csv(os.path.join(out, "combined.csv"), index=False)

    shown = policies[["level", "missing", "policy", "legit_all_%", "legit_nonidentical_%", "e3_shellcode_%", "e6_pages_%"]
                     + [column for column in policies.columns if column.startswith("e6_") and column.endswith("chain_%")]]
    print(shown.to_string(index=False), flush=True)
    print(rules_frame[["rule", "legit_page_fp_accepted", "legit_page_fp_%", "raw_page_fp_%",
                       "raw_page_fp_weighted_%", "expected_fp_pages_in_corpus"]
                      + [column for column in rules_frame.columns if column.endswith("_page_%")]].to_string(index=False))
    print(combined[["level", "missing", "rule"] + [column for column in combined.columns if column.endswith("chain_%")]].to_string(index=False))


if __name__ == "__main__":
    main()
