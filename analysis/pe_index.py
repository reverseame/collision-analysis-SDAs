"""E8: reproducible digest index of the PE files recovered from Windows VMs.

Only files below ``maquinaNNN/NNN{dll,dll64,exe,exe64,sys,sys64}`` are indexed. The
complete VM 107 extraction is intentionally excluded because it overlaps ``maquina107``.

Output: one resumable Parquet shard per batch in OUT/shards.
Usage: python pe_index.py PE_ROOT OUT [WORKERS] [BATCH_SIZE]
"""
import glob
import hashlib
import os
import re
import sys

import pefile
import pyarrow as pa
import pyarrow.parquet as pq
import ssdeep

from sda_common import sdhash_features, sdhash_files, tlsh_digest

MACHINE_DIR = re.compile(r"^maquina(\d+)$")
CATEGORY = re.compile(r"^(\d+)(dll|exe|sys)(64)?$", re.IGNORECASE)
EXTENSIONS = {".dll", ".exe", ".sys"}
FAMILIES = {101: "server", 102: "desktop", 103: "server", 104: "server", 107: "desktop"}
ARCHITECTURES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "arm", 0xAA64: "arm64"}


def discover(root):
    rows = []
    for machine_name in sorted(os.listdir(root)):
        match = MACHINE_DIR.match(machine_name)
        machine_dir = os.path.join(root, machine_name)
        if not match or not os.path.isdir(machine_dir):
            continue
        machine = int(match.group(1))
        for category_name in sorted(os.listdir(machine_dir)):
            category_match = CATEGORY.match(category_name)
            category_dir = os.path.join(machine_dir, category_name)
            if not category_match or int(category_match.group(1)) != machine or not os.path.isdir(category_dir):
                continue
            for dirpath, _, files in os.walk(category_dir):
                for filename in sorted(files):
                    extension = os.path.splitext(filename)[1].lower()
                    if extension not in EXTENSIONS:
                        continue
                    path = os.path.join(dirpath, filename)
                    rows.append((
                        os.path.relpath(path, root),
                        machine,
                        FAMILIES.get(machine, "unknown"),
                        category_match.group(2).lower(),
                        category_name,
                    ))
    return rows


def python_metadata(root, item):
    relpath, machine, family, kind, category = item
    path = os.path.join(root, relpath)
    with open(path, "rb") as handle:
        data = handle.read()
    pe = pefile.PE(data=data, fast_load=True)
    architecture = ARCHITECTURES.get(pe.FILE_HEADER.Machine, f"machine_{pe.FILE_HEADER.Machine:04x}")
    return {
        "path": relpath,
        "machine": machine,
        "family": family,
        "category": category,
        "kind": kind,
        "architecture": architecture,
        "name": os.path.basename(path).lower(),
        "size": len(data),
        "sha256": hashlib.sha256(data).digest(),
        "tlsh": tlsh_digest(data),
        "ssdeep": ssdeep.hash(data),
    }


def main():
    root, out = sys.argv[1], sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    batch_size = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    shard_dir = os.path.join(out, "shards")
    os.makedirs(shard_dir, exist_ok=True)
    inventory = discover(root)
    print(f"PE descubiertos: {len(inventory)}", flush=True)

    errors_path = os.path.join(out, "errors.tsv")
    known_errors = set()
    if os.path.exists(errors_path):
        with open(errors_path, encoding="utf-8") as error_file:
            known_errors = {line.split("\t", 1)[0] for line in error_file if line.strip()}
    indexed = skipped = 0
    for batch_number, start in enumerate(range(0, len(inventory), batch_size)):
        shard = os.path.join(shard_dir, f"{batch_number:05d}.parquet")
        batch = inventory[start:start + batch_size]
        if os.path.exists(shard):
            skipped += pq.ParquetFile(shard).metadata.num_rows
            continue
        metadata = []
        valid_paths = []
        with open(errors_path, "a", encoding="utf-8") as error_file:
            for item in batch:
                try:
                    metadata.append(python_metadata(root, item))
                    valid_paths.append(os.path.join(root, item[0]))
                except (OSError, pefile.PEFormatError, ValueError) as exc:
                    if item[0] not in known_errors:
                        known_errors.add(item[0])
                        error_file.write(f"{item[0]}\t{type(exc).__name__}: {exc}\n")
        digests = sdhash_files(valid_paths, workers, include_scheme=True)
        for row, digest in zip(metadata, digests):
            row["sdhash"] = digest
            row["sdhash_features"] = sdhash_features(digest)
        temporary = shard + ".part"
        pq.write_table(pa.Table.from_pylist(metadata), temporary, compression="zstd")
        os.replace(temporary, shard)
        indexed += len(metadata)
        if (batch_number + 1) % 10 == 0 or start + len(batch) == len(inventory):
            print(
                f"{min(start + len(batch), len(inventory))}/{len(inventory)} examinados, "
                f"{indexed} nuevos, {skipped} existentes, {len(known_errors)} errores",
                flush=True,
            )
    total_indexed = sum(pq.ParquetFile(path).metadata.num_rows for path in glob.glob(os.path.join(shard_dir, "*.parquet")))
    print(f"Hecho: {len(inventory)} examinados, {total_indexed} indexados, {len(known_errors)} errores")


if __name__ == "__main__":
    main()
