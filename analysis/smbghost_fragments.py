"""Fragmentation cost of the SMBGhost kernel shellcode (exploit-db 48537).

Extracts KERNEL_SHELLCODE from the exploit, splits it into its x86-64 code (up to the last
`ret`) and trailing data, and reports how many 11-byte fragments (16 modified bytes per page
minus a 5-byte jump) the code needs when fragments must end at instruction boundaries, how many
naive 11-byte cuts fall inside an instruction, and how many relative branches and RIP-relative
references would have to be rewritten.

Usage: python smbghost_fragments.py EXPLOIT_PY
  (curl -L -o 48537.py https://www.exploit-db.com/raw/48537)
"""
import math
import re
import sys

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

SLOT = 11
PAGE_BYTES = 16


def shellcode(path):
    data = b""
    for line in open(path, encoding="utf-8"):
        match = re.match(r'\s*KERNEL_SHELLCODE\s*(\+?=)\s*(b".*")', line)
        if match:
            chunk = eval(match.group(2))  # literal bytes from the exploit source
            data = chunk if match.group(1) == "=" else data + chunk
    return data


def main(path):
    blob = shellcode(path)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    last_ret = max(i.address + i.size for i in md.disasm(blob, 0) if i.mnemonic == "ret")
    code, data = blob[:last_ret], blob[last_ret:]
    ins = list(md.disasm(code, 0))
    assert ins[-1].address + ins[-1].size == len(code), "code region does not decode cleanly"

    starts = {i.address for i in ins}
    cuts = range(SLOT, len(code), SLOT)
    fragments, used = 1, 0
    for i in ins:
        if used + i.size > SLOT:
            fragments, used = fragments + 1, 0
        used += i.size
    branches = [i for i in ins if i.mnemonic.startswith(("j", "call", "loop"))
                and not i.op_str.startswith(("r", "q"))]

    print(f"shellcode {len(blob)} B: code {len(code)} B ({len(ins)} instructions, "
          f"longest {max(i.size for i in ins)} B), data {len(data)} B")
    print(f"naive 11-byte split of the whole shellcode: {math.ceil(len(blob) / SLOT)} fragments")
    print(f"naive cuts inside an instruction: {sum(c not in starts for c in cuts)} of {len(cuts)}")
    print(f"code fragments on instruction boundaries: {fragments}")
    print(f"data pages without jumps: {math.ceil(len(data) / PAGE_BYTES)}")
    print(f"relative branches: {len(branches)} ({sum(i.size == 2 for i in branches)} rel8); "
          f"RIP-relative references: {sum('rip' in i.op_str for i in ins)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
