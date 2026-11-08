# Experiment container

Debian bookworm + Python 3.11 image with the SDA implementations pinned by commit/version.

| Component | Version | Source |
|---|---|---|
| `sdhash` (CLI binary) | 3.4 | `sdhash/sdhash@db69c8b` (tag `v3.4`), built against Debian's Boost 1.74 (static linking) |
| `sdhash-pairs` | 3.4 | `sdhash-pairs.cc` linked with `libsdbf.a` from the same build: reads `<sdbf A>\t<sdbf B>` pairs from stdin and writes `sdbf::compare` per line (same value as `sdhash -g`, without the Cartesian product of `sdhash -c`) |
| SUM engine (Python 3) | `127d4fb` | `reverseame/similarity-unrelocated-module` (submodule of `reverseame/sum-plugin`) with `marked_pefile@0731e70` and its `pefile@e537035`, in `/opt/sum` (`PYTHONPATH`); dependencies `capstone==5.0.9`, `pefile==2024.8.26` |
| `ssdeep` (Python) | 3.4.1 | `DinoTools/python-ssdeep@becafb0` (tag `3.4.1`; PyPI only goes up to 3.4) |
| libfuzzy | 2.14.1 | Debian bookworm `libfuzzy2` package |
| `tlsh` (Python) | 4.7.2 | PyPI `py-tlsh==4.7.2` (there is no 4.7.1 release) |
| `unicorn` | 2.1.3 | PyPI |
| LaTeX | TeX Live 2022 | for `text.usetex` in the figure scripts |

The remaining Python dependencies are in `requirements.txt` (includes `mysql-connector-python` to query the digest database).

## Build

```bash
docker build -t sda-preservation container
```

## Run

From the repository root, mounting it at `/work` and with your UID so that generated files are not owned by root:

```bash
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/work" sda-preservation
```

One-off commands:

```bash
# Injection PoC (Unicorn) and digest comparison
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work/attack-simulation \
  sda-preservation sh -c 'python generate_exploit.py && python emulate.py && python hashes.py dmps/page_1.dmp -s'

# Figures
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work/graphs \
  sda-preservation python violin.py null_blocks_results.json
```

If the repository is on a FUSE mount (e.g. encfs on `~/Research`) without `allow_other`, the Docker daemon cannot mount it (`error while creating mount source path … file exists`). There are two options: mount the FUSE filesystem with `-o allow_other` (requires `user_allow_other` in `/etc/fuse.conf`) or work on a copy outside the mount:

```bash
rsync -a ./ /tmp/sda-work/
docker run --rm -it --user "$(id -u):$(id -g)" -v /tmp/sda-work:/work sda-preservation
```

## Out of scope

The `extraction-and-analysis/` scripts that call `python2` or import SUM (`similarity-unrelocated-module`) (`extract_page.py`, `extract_collision_pages.py`, `hashes.py`, `test_hashes.py`, `displace_and_hash.py`) are not run in this image.

## Dataset on the experiment host (freya.unizar.es)

| Resource | Location |
|---|---|
| Modules (39,002 ZIP) | `/mnt/DATASETS/modules-Windows/{32-bits,64-bits}` |
| `dataset` database (MariaDB 10.5, MyISAM) | copy of `/var/lib/mysql` in the Docker volume `sda-mysql`, served by the `sda-mariadb` container on the `sda-net` network |
| APOTHEOSIS log and L. Palazón's extractions | `/home/luis/bd/extraction/` |
| On-disk PE files of VMs 101–104 and 107 | `/mnt/DATASETS/PE-Windows-system-files/maquinaNNN/NNN{dll,dll64,exe,exe64,sys,sys64}`. `NNNdll` = System32 (64-bit), `NNNdll64` = SysWOW64 (32-bit). 101–104 and `107{exe64,sys64}`: copy of `valhalla:/mnt/pve/NAS_Backup_Datasets/zhelali/practicas` (24,172 files). Rest of 107: extracted read-only from the disk of VM 107 on valhalla (Windows 10 21H2) and matched to the JSON files by function bytes (`maquina107/MANIFEST_vm107.tsv`; `MRT.exe`, `WdFilter.sys` and `WdDevFlt.sys` are newer than the JSON files). Full extraction with paths in `vm107-extraccion-completa/`, scripts in `scripts/` |
| Per-function analysis (radare2) of those PE files | `/mnt/HOME_VIEJOS/zhelali/archivos/` (28,297 JSON) |

`sda-mariadb` starts with `--skip-grant-tables` and no published ports: it is only reachable from containers on the `sda-net` network, without credentials.

```bash
# Start the database (if it is not running)
docker start sda-mariadb

# Work session with the database and the corpus (read-only); /home is full, work in /var/tmp
docker run --rm -it --network sda-net --user "$(id -u):$(id -g)" \
  -v /mnt/DATASETS/modules-Windows:/data/modules-Windows:ro \
  -v /home/luis/bd/extraction:/data/luis-extraction:ro \
  -v /mnt/DATASETS/PE-Windows-system-files:/data/PE-Windows:ro \
  -v /var/tmp/sda-work:/work \
  sda-preservation
```

From inside: `mysql.connector.connect(host="sda-mariadb", user="root", database="dataset")`.
