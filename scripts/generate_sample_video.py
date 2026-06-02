#!/usr/bin/env python3
"""
Generate a minimal valid MP4 video file for the DRM demo.
Produces a tiny black-screen 1-second video using raw MP4 box construction.
"""
import struct
from pathlib import Path


def u32be(n: int) -> bytes:
    return struct.pack(">I", n)


def u16be(n: int) -> bytes:
    return struct.pack(">H", n)


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def box(fourcc: str, *children: bytes) -> bytes:
    payload = b"".join(children)
    return u32be(len(payload) + 8) + fourcc.encode() + payload


def fullbox(fourcc: str, version: int, flags: int, *children: bytes) -> bytes:
    payload = bytes([version]) + u32be(flags)[1:] + b"".join(children)
    return u32be(len(payload) + 8) + fourcc.encode() + payload


def make_mp4() -> bytes:
    # ftyp box
    ftyp = box("ftyp", b"isom", u32be(512), b"isom", b"iso2", b"mp41")

    # minimal mdat with a single black YUV frame placeholder
    # Just a sequence of null bytes representing compressed video data
    frame_data = bytes(1024)
    mdat = box("mdat", frame_data)
    mdat_offset = len(ftyp)

    # tkhd
    tkhd = fullbox(
        "tkhd", 0, 3,
        u32be(0), u32be(0),   # creation, modification time
        u32be(1),              # track id
        u32be(0),              # reserved
        u32be(90),             # duration (90 = 1s at 90Hz timescale)
        b"\x00" * 8,
        u16be(0), u16be(0),   # layer, alt group
        u16be(0), u16be(0),   # volume, reserved
        # identity matrix
        u32be(0x00010000), u32be(0), u32be(0),
        u32be(0), u32be(0x00010000), u32be(0),
        u32be(0), u32be(0), u32be(0x40000000),
        u32be(320 << 16),     # width (320.0 fixed point)
        u32be(240 << 16),     # height (240.0 fixed point)
    )

    # mdhd
    mdhd = fullbox(
        "mdhd", 0, 0,
        u32be(0), u32be(0),   # creation, modification
        u32be(90000),          # timescale
        u32be(90000),          # duration (1 second)
        u16be(0x55C4),         # language: 'und'
        u16be(0),
    )

    # hdlr
    hdlr = fullbox(
        "hdlr", 0, 0,
        u32be(0),
        b"vide",
        u32be(0), u32be(0), u32be(0),
        b"VideoHandler\x00",
    )

    # stsd - sample description (avc1 placeholder)
    avc1_inner = (
        b"\x00" * 6 +          # reserved
        u16be(1) +              # data reference index
        b"\x00" * 16 +         # reserved
        u16be(320) +            # width
        u16be(240) +            # height
        u32be(0x00480000) +     # horiz resolution 72dpi
        u32be(0x00480000) +     # vert resolution 72dpi
        u32be(0) +              # reserved
        u16be(1) +              # frame count
        b"\x00" * 32 +         # compressor name
        u16be(0x0018) +         # depth
        b"\xff\xff"             # pre-defined
    )
    avc1 = u32be(len(avc1_inner) + 8) + b"avc1" + avc1_inner
    stsd = fullbox("stsd", 0, 0, u32be(1), avc1)

    # stts (time to sample): 1 sample lasting 90000 units
    stts = fullbox("stts", 0, 0, u32be(1), u32be(1), u32be(90000))

    # stsc (sample to chunk): 1 chunk with 1 sample
    stsc = fullbox("stsc", 0, 0, u32be(1), u32be(1), u32be(1), u32be(1))

    # stsz (sample sizes): 1 sample of 1024 bytes
    stsz = fullbox("stsz", 0, 0, u32be(0), u32be(1), u32be(1024))

    # stco (chunk offsets)
    chunk_offset = mdat_offset + 8  # offset to mdat payload
    stco = fullbox("stco", 0, 0, u32be(1), u32be(chunk_offset))

    stbl = box("stbl", stsd, stts, stsc, stsz, stco)
    minf = box("minf", box("vmhd"), box("dinf", fullbox("dref", 0, 0, u32be(1),
               fullbox("url ", 0, 1))), stbl)
    mdia = box("mdia", mdhd, hdlr, minf)
    trak = box("trak", tkhd, mdia)

    # mvhd
    mvhd = fullbox(
        "mvhd", 0, 0,
        u32be(0), u32be(0),
        u32be(1000),
        u32be(1000),
        u32be(0x00010000),
        u16be(0x0100), u16be(0),
        u32be(0), u32be(0),
        u32be(0x00010000), u32be(0), u32be(0),
        u32be(0), u32be(0x00010000), u32be(0),
        u32be(0), u32be(0), u32be(0x40000000),
        u32be(0), u32be(0), u32be(0), u32be(0),
        u32be(0), u32be(0),
        u32be(2),
    )

    moov = box("moov", mvhd, trak)
    return ftyp + mdat + moov


if __name__ == "__main__":
    out = Path(__file__).parent.parent / "artifacts" / "sample_video.mp4"
    out.parent.mkdir(exist_ok=True)
    data = make_mp4()
    out.write_bytes(data)
    print(f"Generated minimal MP4: {out} ({len(data)} bytes)")
