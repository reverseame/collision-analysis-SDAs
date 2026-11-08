"""Where E8 code-cave writes land relative to what the Windows loader maps.

A cave in E8 is a null run inside the raw bytes of an executable section
[PointerToRawData, PointerToRawData + SizeOfRawData). The loader maps a section as VirtualSize
bytes rounded up to SectionAlignment, so raw bytes beyond that are not section content in memory.
Each write is classified as:

  virtual    inside [0, VirtualSize) of the section
  tail_page  beyond VirtualSize but inside VirtualSize rounded up to SectionAlignment
  unmapped   beyond the aligned VirtualSize (executing there needs a patched section header)

Preservation results are then split by class, for the E8 shellcode writes and for the E4-on-PE
code-cave winners.

Usage: python pe_cave_mapping.py E8_MARGIN_TRIALS E8_OPTIMIZED_TRIALS PE_ROOT OUT
"""
import os
import sys

import pandas as pd
import pefile

CLASSES = ("virtual", "tail_page", "unmapped")


def classify(image, start, end):
    alignment = int(image.OPTIONAL_HEADER.SectionAlignment) or 0x1000
    for section in image.sections:
        if not section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        raw_start = int(section.PointerToRawData)
        if not raw_start <= start < raw_start + int(section.SizeOfRawData):
            continue
        virtual = int(section.Misc_VirtualSize) or int(section.SizeOfRawData)
        aligned = -(-virtual // alignment) * alignment
        if end <= raw_start + virtual:
            return "virtual"
        if end <= raw_start + aligned:
            return "tail_page"
        return "unmapped"
    return "not_executable"


def classify_rows(frame, root, offset_column, size_column):
    cache, classes = {}, []
    for row in frame.itertuples(index=False):
        if row.artifact_id not in cache:
            cache[row.artifact_id] = pefile.PE(os.path.join(root, row.artifact_id), fast_load=True)
        start = int(getattr(row, offset_column))
        classes.append(classify(cache[row.artifact_id], start, start + int(getattr(row, size_column))))
    return classes


def main():
    margin_dir, optimized_dir, root, out = sys.argv[1:5]
    os.makedirs(out, exist_ok=True)

    trials = pd.read_parquet(margin_dir)
    cave = trials[
        (trials.attempted == True) & (trials.changed == True)  # noqa: E712
        & (trials.placement == "code_cave") & (trials.content == "shellcode")
    ].copy()
    cave["mapping"] = classify_rows(cave, root, "offset", "write_size")
    rows = []
    for (size, mapping), group in cave.groupby(["write_size", "mapping"]):
        sdhash = group[group.sdhash_score.notna()]
        rows.append({
            "write_size": size, "mapping": mapping, "writes": len(group),
            "ssdeep_exact": int(group.ssdeep_exact.astype(bool).sum()),
            "tlsh_median": group.tlsh_dist.median(),
            "sdhash_comparable": len(sdhash), "sdhash_100": int((sdhash.sdhash_score == 100).sum()),
        })
    margin = pd.DataFrame(rows)
    margin.to_csv(os.path.join(out, "e8_cave_mapping.csv"), index=False)
    print("E8, shellcode en cuevas:", cave.mapping.value_counts().to_dict())
    print(margin.to_string(index=False))

    optimized = pd.read_parquet(optimized_dir)
    optimized = optimized[(optimized.scope == "code_cave") & optimized.optimized_comparable.eq(True)].copy()
    optimized["write_size"] = optimized.payload_size + optimized.optimized_padding.ne("none") * optimized.padding_size
    optimized["write_offset"] = optimized.optimized_offset - optimized.optimized_padding.str.startswith("pre_") * optimized.padding_size
    optimized["mapping"] = classify_rows(optimized, root, "write_offset", "write_size")
    rows = []
    for (algorithm, mapping), group in optimized.groupby(["algorithm", "mapping"]):
        rows.append({
            "algorithm": algorithm, "mapping": mapping, "winners": len(group),
            "exact": int(group.optimized_exact.eq(True).sum()),
            "saturated": int(group.optimized_saturated.eq(True).sum()),
        })
    winners = pd.DataFrame(rows)
    winners.to_csv(os.path.join(out, "e4_pe_cave_mapping.csv"), index=False)
    print("\nE4 sobre PE, ganadores en cuevas:")
    print(winners.to_string(index=False))


if __name__ == "__main__":
    main()
