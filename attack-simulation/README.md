Legacy code from the conference version of the paper: it needs the original MySQL database (available on request only) and raw memory pages that are not redistributed (`dmps/*.dmp` is excluded from this repository and deposited in a restricted-access Zenodo record).

This directory contains the files needed to run memory emulation tests and code injection attacks in a simulated environment. The scripts copy memory dump files, emulate code execution and log events during the process.

# The main files are:
1. generate_exploit.py: Generates an exploit to be injected into the emulated memory.
2. cp_dmps.py: Copies the memory dump files that meet certain criteria, building our attack perimeter.
3. emulate.py: Performs the memory emulation, injecting the exploit and logging events.
4. leer_dmp.py: Reads memory dump files.
5. The digest comparison of these dumps, and its generalization to traceable chains, is in `../analysis/chain_attack.py` (E6). `hashes.py` only checks equality of the last field of `sdhash`; it does not compute a score or apply the 16-feature minimum.
