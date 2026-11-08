"""Why TLSH tolerates writes at the start of a page.

E3 found that a 1-byte write at byte 0 keeps the TLSH digest identical in 70.7% of the pages,
while writes elsewhere almost never do. This script re-implements the TLSH 4.7.2 state that a
write can change (sliding-window bucket counts, one-byte checksum, quartiles and the 128 bucket
codes), checks that it reproduces every digest of the E3 pool and the stored E3 outcomes at the
quarter boundaries, and then writes one byte (0xB8, the first payload byte) at selected
positions of every pool page.

TLSH (src/tlsh_impl.cpp, fast_update) processes windows a[i-4..i] for i >= 4. Each window adds
six triplets, all containing a[i], to the buckets, and updates the checksum with (a[i], a[i-1]).
Hence byte k enters 3 * (number of windows that contain it) triplets, plus 3 more when it is the
newest byte of its window, and bytes 0-2 never enter the checksum.

Usage: python tlsh_position.py E3_POOL E3_TRIALS_DIR OUT_DIR
"""
import os
import sys

import numpy as np
import pandas as pd

V = np.array([
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
], dtype=np.uint8)

# (salt, offsets of the two older bytes) for the six triplets of fast_update; the newest byte
# a[i] is always the first operand.
TRIPLETS = ((49, 1, 2), (12, 1, 3), (178, 2, 3), (166, 2, 4), (84, 1, 4), (230, 3, 4))
SHELLCODE = b"\xB8\x01\x00\x00\x00\xBB\x02\x00\x00\x00\xB9\x03\x00\x00\x00\xCC"
POSITIONS = (0, 1, 2, 3, 4, 5, 8, 64, 1024, 2048, 3072, 4091, 4092, 4093, 4094, 4095)
SIZES = (1, 4, 16)
QUARTERS = {"q1": 0, "q2": 1024, "q3": 2048, "q4": 3072}


def window_buckets(a, start, stop):
    """Bucket index of each triplet for windows start..stop-1 (shape: windows x 6)."""
    i = np.arange(start, stop)
    out = np.empty((len(i), 6), dtype=np.uint8)
    for t, (salt, x, y) in enumerate(TRIPLETS):
        out[:, t] = V[V[V[salt ^ a[i]] ^ a[i - x]] ^ a[i - y]]
    return out


def checksums(a):
    """Checksum after each window; index k is the value after window k (k >= 4)."""
    c = np.zeros(len(a), dtype=np.int64)
    value = 0
    for i in range(4, len(a)):
        value = int(V[V[V[1 ^ a[i]] ^ a[i - 1]] ^ value])
        c[i] = value
    return c


class State:
    """TLSH 4.7.2 state of one input: bucket counts, checksum chain and digest fields."""

    def __init__(self, data):
        self.a = np.frombuffer(data, dtype=np.uint8).astype(np.int64)
        self.n = len(self.a)
        self.idx = window_buckets(self.a, 4, self.n)
        self.counts = np.bincount(self.idx.ravel(), minlength=256)
        self.chk = checksums(self.a)

    def mutate(self, offset, payload):
        """Fields of the digest after writing payload at offset, plus mechanism counters."""
        a = self.a.copy()
        a[offset:offset + len(payload)] = np.frombuffer(payload, dtype=np.uint8)
        changed = np.flatnonzero(a != self.a)
        if len(changed) == 0:
            return None
        lo, hi = int(changed[0]), int(changed[-1])
        w0, w1 = max(4, lo), min(self.n, hi + 5)
        new_idx = window_buckets(a, w0, w1)
        old_idx = self.idx[w0 - 4:w1 - 4]
        counts = self.counts.copy()
        np.subtract.at(counts, old_idx.ravel(), 1)
        np.add.at(counts, new_idx.ravel(), 1)
        # Each checksum step is a bijection of the previous value for a fixed byte pair, so
        # the final checksum differs iff it differs after the last window whose pair changed.
        c0, c1 = max(4, lo), min(self.n, hi + 2)
        value = int(self.chk[c0 - 1]) if c0 > 4 else 0
        for i in range(c0, c1):
            value = int(V[V[V[1 ^ a[i]] ^ a[i - 1]] ^ value])
        checksum_changed = c0 < c1 and value != int(self.chk[c1 - 1])
        hit = set(changed.tolist())
        affected = sum(
            1 for i in range(w0, w1) for (_, x, y) in TRIPLETS
            if i in hit or i - x in hit or i - y in hit
        )
        return {
            "changed_bytes": len(changed),
            "affected_triplets": affected,
            "moved_triplets": int((new_idx != old_idx).sum()),
            "buckets_changed": int((counts[:128] != self.counts[:128]).sum()),
            "checksum_changed": bool(checksum_changed),
            "fields": fields(counts),
        }


def fields(counts):
    """Quartiles, quartile ratios and 2-bit codes of the 128 effective buckets (or None)."""
    eff = counts[:128]
    q1, q2, q3 = (int(v) for v in np.sort(eff)[[31, 63, 95]])
    if q3 == 0 or int((eff > 0).sum()) <= 64:
        return None
    codes = np.where(eff > q3, 3, np.where(eff > q2, 2, np.where(eff > q1, 1, 0)))
    q1r = int(np.float32(q1 * 100) / np.float32(q3)) % 16
    q2r = int(np.float32(q2 * 100) / np.float32(q3)) % 16
    return (q1r, q2r, codes)


def digest(state, f, lvalue_hex, checksum):
    """Hex digest without the T1 prefix, as stored in the E0 index."""
    if f is None:
        return "-"
    q1r, q2r, codes = f
    swap = lambda b: ((b & 0x0F) << 4) | (b >> 4)
    body = bytes(
        int(codes[4 * i] | codes[4 * i + 1] << 2 | codes[4 * i + 2] << 4 | codes[4 * i + 3] << 6)
        for i in range(31, -1, -1)
    )
    head = bytes([swap(checksum)]).hex() + lvalue_hex + bytes([swap(q1r | q2r << 4)]).hex()
    return (head + body.hex()).upper()


def main(pool_path, trials_dir, out):
    os.makedirs(out, exist_ok=True)
    pool = pd.read_parquet(pool_path, columns=["artifact_id", "stratum", "data", "tlsh"])
    pool = pool[pool.tlsh != "-"].reset_index(drop=True)

    states, mismatches = {}, 0
    for row in pool.itertuples(index=False):
        s = State(row.data)
        f = fields(s.counts)
        if digest(s, f, row.tlsh[2:4], int(s.chk[-1])) != row.tlsh:
            mismatches += 1
        s.lvalue_hex, s.fields = row.tlsh[2:4], f
        states[row.artifact_id] = s
    print(f"digest reproduction: {len(pool) - mismatches}/{len(pool)} pool digests identical")
    if mismatches:
        sys.exit("re-implementation does not match TLSH 4.7.2")

    def outcome(s, offset, payload):
        r = s.mutate(offset, payload)
        if r is None:
            return None
        f = r.pop("fields")
        if f is None:
            r.update(comparable=False)
            return r
        q1r, q2r, codes = f
        oq1, oq2, ocodes = s.fields
        r.update(
            comparable=True,
            codes_changed=int((codes != ocodes).sum()),
            qratio_changed=(q1r, q2r) != (oq1, oq2),
        )
        r["identical"] = not r["checksum_changed"] and r["codes_changed"] == 0 and not r["qratio_changed"]
        return r

    # 1. The stored E3 outcomes at quarter boundaries must be reproduced exactly.
    rows = []
    for q, base in QUARTERS.items():
        for size in SIZES:
            t = pd.read_parquet(os.path.join(trials_dir, f"{q}__shellcode__{size:06d}.parquet"))
            t = t[t.changed & t.tlsh_dist.notna()]
            for tr in t.itertuples(index=False):
                r = outcome(states[tr.artifact_id], int(tr.offset), SHELLCODE[:size])
                if r is None or not r["comparable"]:
                    continue
                if r["identical"] != bool(tr.tlsh_tau95):
                    sys.exit(f"E3 mismatch: {q} {size} {tr.artifact_id}")
                rows.append({"placement": q, "write_size": size, "offset": int(tr.offset), **r})
    e3 = pd.DataFrame(rows)
    e3_summary = e3.groupby(["placement", "write_size"]).agg(
        pages=("identical", "size"),
        identical_pct=("identical", lambda s: 100 * s.mean()),
        checksum_changed_pct=("checksum_changed", lambda s: 100 * s.mean()),
        median_affected_triplets=("affected_triplets", "median"),
        median_buckets_changed=("buckets_changed", "median"),
        codes_unchanged_pct=("codes_changed", lambda s: 100 * (s == 0).mean()),
    ).reset_index()
    print(f"E3 reproduction: {len(e3)} comparable trials, all TLSH tau95 outcomes identical")
    e3_summary.to_csv(os.path.join(out, "tlsh_quarter_mechanism.csv"), index=False)
    print(e3_summary.to_string(index=False))

    # 2. One byte at fixed positions of every pool page.
    rows = []
    for aid, s in states.items():
        for p in POSITIONS:
            r = outcome(s, p, SHELLCODE[:1])
            if r is not None and r["comparable"]:
                rows.append({"position": p, **r})
    sweep = pd.DataFrame(rows)
    summary = sweep.groupby("position").agg(
        pages=("identical", "size"),
        affected_triplets=("affected_triplets", "median"),
        identical_pct=("identical", lambda s: 100 * s.mean()),
        checksum_changed_pct=("checksum_changed", lambda s: 100 * s.mean()),
        codes_unchanged_pct=("codes_changed", lambda s: 100 * (s == 0).mean()),
        median_buckets_changed=("buckets_changed", "median"),
    ).reset_index()
    summary.to_csv(os.path.join(out, "tlsh_position_sweep.csv"), index=False)
    print(summary.to_string(index=False))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
