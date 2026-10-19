#!/usr/bin/env python3
"""Independent stdlib construction of semantic-v9/profile-5 stream records."""
from pathlib import Path
import hashlib
import struct
import sys

ROOT = Path(__file__).resolve().parent
MAGIC = b"ASM\x01"
SEMANTIC, PROFILE = 9, 5
MIB = 1024 * 1024
BATCH, WINDOW = 16 * MIB, 17 * MIB
TOTAL = 17 * MIB + 4


def u16(value): return struct.pack(">H", value)
def u32(value): return struct.pack(">I", value)
def u64(value): return struct.pack(">Q", value)


def attempt(stream=b"\x11" * 32, nonce=b"\x22" * 32, sequence=0):
    return stream + nonce + u64(sequence)


def publication(tag, signed):
    return MAGIC + bytes([tag]) + u16(SEMANTIC) + u16(PROFILE) + u32(len(signed)) + signed


def publication_resume(plain=0, wire=0, next_segment=0, generation=0,
                       direction=2, stream=b"\x11" * 32, open_digest=b"\x44" * 32,
                       plain_commit=b"\x01" * 32, cipher_commit=b"\x01" * 32):
    return (MAGIC + b"\xe0" + u16(SEMANTIC) + u16(PROFILE) + bytes([direction])
            + stream + open_digest + u64(plain) + u64(wire) + u64(next_segment)
            + plain_commit + cipher_commit + u64(generation))


def stream_open(semantic=SEMANTIC, profile=PROFILE, stream=b"\x11" * 32,
                nonce=b"\x22" * 32, generation=0):
    return (MAGIC + b"\xd6\x01\x02" + u16(semantic) + u16(profile)
            + b"\x33" * 32 + u64(7) + stream + b"\x44" * 32 + nonce
            + u64(generation))


def accept(plain, cipher, next_segment, generation, credit,
           plain_commit=b"\x51" * 32, cipher_commit=b"\x52" * 32,
           sequence=0, stream=b"\x11" * 32, nonce=b"\x22" * 32):
    return (MAGIC + b"\xd7" + attempt(stream, nonce, sequence)
            + u64(plain) + u64(cipher) + u64(next_segment)
            + plain_commit + cipher_commit + u64(generation) + u64(credit)
            + u32(MIB) + u32(BATCH))


def data(offset=0, body=b"segment", sequence=1, stream=b"\x11" * 32,
         nonce=b"\x22" * 32):
    return MAGIC + b"\xd8" + attempt(stream, nonce, sequence) + u64(offset) + u32(len(body)) + body


def checkpoint(plain, cipher, next_segment, generation, credit,
               plain_commit=b"\x61" * 32, cipher_commit=b"\x62" * 32,
               sequence=2, stream=b"\x11" * 32, nonce=b"\x22" * 32):
    return (MAGIC + b"\xd9" + attempt(stream, nonce, sequence)
            + u64(plain) + u64(cipher) + u64(next_segment)
            + plain_commit + cipher_commit + u64(generation) + u64(credit))


def finish(signed=b"signed-final", plain=TOTAL, cipher=TOTAL + 18 * 16,
           sequence=3, stream=b"\x11" * 32, nonce=b"\x22" * 32):
    return (MAGIC + b"\xda" + attempt(stream, nonce, sequence)
            + u64(plain) + u64(cipher) + u32(len(signed)) + signed)


def result(code=1, plain=TOTAL, cipher=TOTAL + 18 * 16, sequence=4,
           stream=b"\x11" * 32, nonce=b"\x22" * 32):
    return (MAGIC + b"\xdb" + attempt(stream, nonce, sequence)
            + u64(plain) + u64(cipher) + bytes([code])
            + b"\x71" * 32 + b"\x72" * 32)


def result_ack(sequence=5, stream=b"\x11" * 32, nonce=b"\x22" * 32):
    return MAGIC + b"\xdc" + attempt(stream, nonce, sequence) + b"\x72" * 32


def sequence(*frames):
    return u16(len(frames)) + b"".join(u32(len(frame)) + frame for frame in frames)


def profile5_corpus():
    rows = []
    def add(ok, kind, name, wire):
        rows.append(("ACCEPT" if ok else "REJECT", kind, name, wire.hex()))

    signed_open = b"publisher-signed-provisional-open"
    signed_final = b"publisher-signed-final-commitment"
    add(True, "publication-open", "signed", publication(0xdd, signed_open))
    add(True, "publication-commit", "signed", publication(0xde, signed_final))
    add(True, "publication-resume", "initial", publication_resume())
    add(True, "publication-resume", "one-segment",
        publication_resume(MIB, MIB + 178, 1, 1,
                           plain_commit=b"\x51" * 32, cipher_commit=b"\x52" * 32))
    add(True, "open", "fresh-attempt", stream_open())
    for name, values in [
        ("zero", (0, 0, 0, 0, WINDOW)),
        ("one-segment", (MIB, MIB + 16, 1, 1, MIB + 16 + WINDOW)),
        ("durability-batch", (BATCH, BATCH + 16 * 16, 16, 2, BATCH + 16 * 16 + WINDOW)),
        ("final", (TOTAL, TOTAL + 18 * 16, 18, 3, TOTAL + 18 * 16 + WINDOW)),
    ]:
        add(True, "accept", name, accept(*values))
    add(True, "data", "bounded-body", data())
    add(True, "checkpoint", "cumulative",
        checkpoint(BATCH, BATCH + 16 * 16, 16, 2, BATCH + 16 * 16 + WINDOW))
    add(True, "finish", "signed-final", finish(signed_final))
    add(True, "result", "promoted", result())
    add(True, "result-ack", "settled", result_ack())

    add(False, "open", "zero-stream-id", stream_open(stream=b"\0" * 32))
    add(False, "open", "zero-attempt-nonce", stream_open(nonce=b"\0" * 32))
    add(False, "open", "wrong-semantic", stream_open(semantic=8))
    add(False, "open", "wrong-profile", stream_open(profile=4))
    add(False, "data", "zero-body", data(body=b""))
    add(False, "data", "oversized-body", data(body=b"X" * (MIB + 1)))
    add(False, "data", "offset-overflow", data(offset=(1 << 64) - 1, body=b"XX"))
    add(False, "accept", "credit-below-durable", accept(MIB, MIB + 16, 1, 1, MIB))
    add(False, "accept", "window-too-small", accept(0, 0, 0, 0, BATCH))
    add(False, "checkpoint", "zero-accumulator",
        checkpoint(MIB, MIB + 16, 1, 1, MIB + 16 + WINDOW, plain_commit=b"\0" * 32))
    add(False, "publication-open", "trailing", publication(0xdd, signed_open) + b"\0")
    add(False, "publication-commit", "oversized", publication(0xde, b"X" * (MIB + 1)))
    add(False, "publication-resume", "zero-stream-id",
        publication_resume(stream=b"\0" * 32))
    add(False, "publication-resume", "generation-zero-with-progress",
        publication_resume(MIB, MIB + 178, 1, 0))
    add(False, "publication-resume", "wrong-initial-commitment",
        publication_resume(plain_commit=b"\x51" * 32))

    initial = accept(0, 0, 0, 0, WINDOW)
    first_data = data(0, b"A" * 32, 1)
    add(False, "sequence", "gap", sequence(initial, data(64, b"B" * 32, 1)))
    add(False, "sequence", "overlap", sequence(initial, first_data, data(16, b"B" * 32, 2)))
    add(False, "sequence", "credit-regression", sequence(
        initial,
        checkpoint(MIB, MIB + 16, 1, 1, MIB + 16 + WINDOW, sequence=2),
        checkpoint(2 * MIB, 2 * MIB + 32, 2, 2, MIB + 16 + WINDOW - 1, sequence=3)))
    add(False, "sequence", "accumulator-mismatch", sequence(
        initial,
        checkpoint(MIB, MIB + 16, 1, 1, MIB + 16 + WINDOW,
                   plain_commit=b"\x99" * 32, sequence=2)))
    return "# aster-blob-stream-records/v2\tsemantic=9\tprofile=5\toracle=python-stdlib\n" + "".join(
        "\t".join(row) + "\n" for row in rows)


def range_request(offset=0, total=32768, length=16384, direction=2):
    return (b"ASM\x01\xa1" + bytes([direction]) + b"\x01" * 32
            + b"\x02" * 33 + struct.pack(">QQI", total, offset, length)
            + b"\x03" * 32)


def range_schedule(*entries):
    return b"ABRS\x01" + u16(len(entries)) + b"".join(entries)


def range_digest(value):
    return hashlib.sha256(b"ASTER/blob-ranges-stream/schedule/v1\0" + value).digest()


def profile4_corpus():
    rows = []
    def add(ok, kind, name, wire):
        rows.append(("ACCEPT" if ok else "REJECT", kind, name, wire.hex()))

    first, second = range_request(), range_request(16384)
    base = range_schedule(first, second)
    for name, wire in [
        ("empty", range_schedule()), ("two", base),
        ("resume", range_schedule(second)),
        ("maximum", range_schedule(*(range_request(i * 16384, 64 * 16384)
                                      for i in range(64)))),
    ]:
        add(True, "schedule", name, wire)
    for name, wire in [
        ("duplicate", range_schedule(first, first)),
        ("reversed", range_schedule(second, first)),
        ("gap", range_schedule(range_request(0, 65536), range_request(32768, 65536))),
        ("total-conflict", range_schedule(first, range_request(16384, 32769))),
        ("direction", range_schedule(range_request(direction=1))),
        ("zero-length", range_schedule(range_request(length=0))),
        ("oversize-range", range_schedule(range_request(length=16385))),
        ("noncanonical", range_schedule(range_request(length=1))),
        ("count-limit", b"ABRS\x01" + u16(65) + first * 65),
        ("count-mismatch", b"ABRS\x01" + u16(3) + first + second),
        ("truncated", base[:-1]), ("trailing", base + b"\0"),
        ("version", b"ABRS\x02" + base[5:]),
        ("source", range_schedule(first, second[:6] + b"\x04" + second[7:])),
        ("proof", range_schedule(first, second[:-1] + b"\x04")),
    ]:
        add(False, "schedule", name, wire)
    single = range_schedule(range_request(total=1, length=1))
    binding = range_digest(single)
    data = (b"ABRD\x01" + binding + u16(0) + b"ASM\x01\xa2"
            + single[12:98] + b"\x01" + struct.pack(">I", 1) + b"Z")
    unavailable = data[:130] + b"\x02" + struct.pack(">I", 0)
    add(True, "data", "one-byte", data)
    add(True, "data", "unavailable", unavailable)
    for name, wire in [
        ("truncated", data[:-1]), ("trailing", data + b"\0"),
        ("digest", data[:5] + b"\0" * 32 + data[37:]),
        ("index", data[:37] + u16(1) + data[39:]),
        ("direction", data[:44] + b"\x01" + data[45:]),
        ("source", data[:45] + b"\x04" + data[46:]),
        ("object", data[:77] + b"\x01" + data[78:]),
        ("status", data[:130] + b"\x03" + data[131:]),
        ("unavailable-payload", data[:130] + b"\x02" + data[131:]),
        ("payload-length", data[:131] + struct.pack(">I", 2) + b"Z"),
    ]:
        add(False, "data", name, wire)
    terminal = b"ABRE\x01" + binding + u16(1)
    add(True, "terminal", "complete", terminal)
    for name, wire in [
        ("truncated", terminal[:-1]), ("trailing", terminal + b"\0"),
        ("digest", terminal[:5] + b"\0" * 32 + terminal[37:]),
        ("count", terminal[:37] + u16(0)), ("kind", b"ABRD" + terminal[4:]),
    ]:
        add(False, "terminal", name, wire)
    return "# aster-blob-stream-records/v1\toracle=python-stdlib\n" + "".join(
        "\t".join(row) + "\n" for row in rows)


def main():
    offer = ("# aster-blob-ranges-stream-vectors/v1\tsemantic=7,8\toracle=python-stdlib\n"
             "ACCEPT\toffer-blob-stream-only-v1\t"
             "0105000501000100040100040003010001000201000100010200020001\n")
    outputs = {
        "blob-ranges-stream-v1.tsv": offer,
        "blob-stream-records-v1.tsv": profile4_corpus(),
        "blob-stream-records-v2.tsv": profile5_corpus(),
    }
    for name, text in outputs.items():
        path = ROOT / "vectors" / name
        if "--write" in sys.argv:
            path.write_text(text)
        else:
            assert path.read_text() == text, f"{path}: differs from independent construction"
    seed = ROOT.parent / "fuzz/corpus/selected_frame_decode/blob-stream-only-offer-v1"
    seed_bytes = b"ASM\x01\xd1" + bytes.fromhex(offer.splitlines()[1].split("\t")[2])
    if "--write" in sys.argv:
        seed.write_bytes(seed_bytes)
    else:
        assert seed.read_bytes() == seed_bytes, "fuzz offer seed differs"
    print("Blob stream oracle: replacement corpus and fuzz offer match independent construction")


if __name__ == "__main__":
    main()
