from __future__ import annotations

import ipaddress
from typing import Any, Dict


def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", "").replace(" ", "").strip())


def _u32_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "big")


def _u16_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 2], "big")


def _u16_le(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 2], "little")


def _ip4(b4: bytes) -> str:
    return str(ipaddress.IPv4Address(b4))


def _expected_app_data_len_from_rtcp_length(rtcp_length_words_minus1: int) -> int:
    # RTCP bytes = (length+1)*4. APP header (ssrc+name included) is 12 bytes.
    return (rtcp_length_words_minus1 + 1) * 4 - 12


def parse_avaya_rtcp_subtype4(
    *,
    rtcp_length: int,
    app_name: str,
    app_data_hex: str,
    strict_length: bool = True,
) -> Dict[str, Any]:
    """
    Master parser for Avaya RTCP APP subtype=4 packets (PT=204, name "-AV-"),
    based on the confirmed layouts from your pcap+debug pairs.

    Common prefix (offsets within app.data):
      0x00 u32  RTCP-SSRC / RTP-SSRC (monitored stream SSRC)
      0x04 u32  Sub4-Mask
      0x08 u32  Rtp-count
      0x0C u32  Rtp-octet-count

    Variants by app.data length (derived from rtcp.length):
      - 28 bytes (rtcp.length=9): compact: RTT + DSCP/TTL + payload + incoming ports
      - 32 bytes (rtcp.length=10): RTT + JB delay + reserved + max jitter + DSCP/TTL + payload + incoming ports
      - 36 bytes (rtcp.length=11): RTT + remote_ip/remote_rtcp_port + payload/TTL/DSCP/encrypt/silence + incoming ports
      - 40 bytes (rtcp.length=12): (seen in your earlier samples; fields not fully nailed; parsed conservatively)
      - 56 bytes (rtcp.length=16): long: many metrics + local/remote-ish tail (not fully nailed; parsed conservatively)

    Important endian note:
      - Incoming RTP ports are LITTLE-endian (confirmed by debug pairs).
      - DSCP/TTL are byte fields; in your captures DSCP=0, TTL=56.
      - In len=36, media_encryption/silence_suppression are explicit bytes (e.g., 0x02/0x00).
      - In len=32, those are NOT present; debug prints defaults (0).
    """
    if app_name != "-AV-":
        raise ValueError(f"Unexpected app_name {app_name!r}; expected '-AV-'")

    data = _hex_to_bytes(app_data_hex)
    expected = _expected_app_data_len_from_rtcp_length(rtcp_length)
    if strict_length and len(data) != expected:
        raise ValueError(f"app.data length {len(data)} != expected {expected} from rtcp.length={rtcp_length}")

    if len(data) < 16:
        raise ValueError(f"Subtype-4 app.data too short: {len(data)} bytes")

    base: Dict[str, Any] = {
        "rtcp_length": rtcp_length,
        "app_data_len": len(data),
        "type": f"len{len(data)}",
        "rtcp_ssrc_be": f"0x{_u32_be(data, 0):08x}",
        "sub4_mask_be": f"0x{_u32_be(data, 4):08x}",
        "rtp_count": _u32_be(data, 8),
        "rtp_octet_count": _u32_be(data, 12),
    }

    # ---------------- len=28 (rtcp.length=9) ----------------
    # Confirmed by your pair:
    #   RTT at 0x10
    #   DSCP/TTL at 0x12..0x13 (bytes)
    #   RTP payload at 0x14
    #   Incoming ports: src at 0x15..0x16 (LE), dst at 0x17..0x18 (LE)
    #   Pad at 0x19..0x1B
    if len(data) == 28:
        base["type"] = "len28_compact"
        base["round_trip_time"] = _u16_be(data, 0x10)
        base["rtp_dscp"] = data[0x12]
        base["rtp_ttl"] = data[0x13]
        base["rtp_payload"] = data[0x14]
        base["incoming_rtp_src_port"] = _u16_le(data, 0x15)
        base["incoming_rtp_dst_port"] = _u16_le(data, 0x17)
        base["pad_hex"] = data[0x19:0x1C].hex()
        return base

    # ---------------- len=32 (rtcp.length=10) ----------------
    # Confirmed by your pair:
    #   RTT 0x10, JB delay 0x12
    #   reserved u16 at 0x14 (0 in your sample)
    #   max jitter u32 at 0x16
    #   DSCP/TTL bytes at 0x1A..0x1B
    #   RTP payload at 0x1C
    #   Incoming ports: src 0x1D..0x1E (LE), dst 0x1F..0x20 (LE)
    #   pad at 0x21
    if len(data) == 32:
        base["type"] = "len32_jb_maxjitter_compact_tail"
        base["round_trip_time"] = _u16_be(data, 0x10)
        base["jitter_buf_delay"] = _u16_be(data, 0x12)
        base["reserved_u16"] = _u16_be(data, 0x14)
        base["max_jitter"] = _u32_be(data, 0x16)
        base["rtp_dscp"] = data[0x1A]
        base["rtp_ttl"] = data[0x1B]
        base["rtp_payload"] = data[0x1C]
        base["incoming_rtp_src_port"] = _u16_le(data, 0x1D)
        base["incoming_rtp_dst_port"] = _u16_le(data, 0x1F)
        base["pad"] = data[0x21]
        # fields shown as 0 in debug but NOT present here; keep them explicit as "implied"
        base["media_encryption_implied"] = 0
        base["silence_suppression_implied"] = 0
        base["packetization_time_implied"] = 0
        return base

    # ---------------- len=36 (rtcp.length=11) ----------------
    # Confirmed by your pair:
    #   RTT at 0x10
    #   0x12..0x15 looks like remote IP (often a2:f8:a8:xx in your captures) even if debug prints empty
    #   0x16..0x17 remote RTCP port candidate (endianness not 100% pinned; keep both)
    #   0x18 payload, 0x1A TTL, 0x1B DSCP, 0x1C media_encryption, 0x1D silence_suppression
    #   incoming ports at 0x1E and 0x20 are LE (confirmed)
    if len(data) == 36:
        base["type"] = "len36_remote_block_plus_codec_flags"
        base["round_trip_time"] = _u16_be(data, 0x10)

        base["remote_ip_candidate"] = _ip4(data[0x12:0x16])
        base["remote_rtcp_port_candidate_le"] = _u16_le(data, 0x16)
        base["remote_rtcp_port_candidate_be"] = _u16_be(data, 0x16)

        base["rtp_payload"] = data[0x18]
        base["frame_or_mode_u8"] = data[0x19]
        base["rtp_ttl"] = data[0x1A]
        base["rtp_dscp"] = data[0x1B]
        base["media_encryption"] = data[0x1C]
        base["silence_suppression"] = data[0x1D]
        base["incoming_rtp_src_port"] = _u16_le(data, 0x1E)
        base["incoming_rtp_dst_port"] = _u16_le(data, 0x20)
        base["pad_hex"] = data[0x22:0x24].hex()
        return base

    # ---------------- len=40 (rtcp.length=12) ----------------
    # Seen in your examples but not fully pinned with debug.
    # Parse safely: two u32s after prefix, then a plausible remote IP + remote port block,
    # keep remaining as raw. (Do NOT over-claim semantics.)
    if len(data) == 40:
        base["type"] = "len40_unconfirmed_variant"
        base["field_u32_a_guess"] = _u32_be(data, 0x10)
        base["field_u32_b_guess"] = _u32_be(data, 0x14)
        base["remote_ip_candidate"] = _ip4(data[0x18:0x1C])
        base["remote_port_candidate_be"] = _u16_be(data, 0x1C)
        base["remote_port_candidate_le"] = _u16_le(data, 0x1C)
        base["tail_raw_hex"] = data[0x1E:].hex()
        return base

    # ---------------- len=56 (rtcp.length=16) ----------------
    # Seen in your examples; not fully pinned with debug.
    # Keep it conservative; expose stable metrics-ish fields and the whole tail.
    if len(data) == 56:
        base["type"] = "len56_long_unconfirmed"
        base["rtt_u16_guess"] = _u16_be(data, 0x10)
        base["jb_delay_u16_guess"] = _u16_be(data, 0x12)
        base["largest_seq_jump_u16_guess"] = _u16_be(data, 0x14)
        base["largest_seq_fall_u16_guess"] = _u16_be(data, 0x16)
        base["max_jitter_u32_guess"] = _u32_be(data, 0x18)
        base["seq_jump_instances_u16_guess"] = _u16_be(data, 0x1C)
        base["seq_fall_instances_u16_guess"] = _u16_be(data, 0x1E)
        base["reserved_u32_at_0x20"] = f"0x{_u32_be(data, 0x20):08x}"

        # Tail: your earlier captures looked like a leading byte + IPv4 at 0x25..0x28
        base["tail_raw_hex"] = data[0x24:].hex()
        base["tail_leading_u8_guess"] = data[0x24]
        base["remote_ip_candidate_guess"] = _ip4(data[0x25:0x29])
        base["remote_port_candidate_be"] = _u16_be(data, 0x29)
        base["remote_port_candidate_le"] = _u16_le(data, 0x29)
        return base

    # ---------------- fallback (unknown length) ----------------
    base["type"] = f"len{len(data)}_unknown"
    base["tail_raw_hex"] = data[16:].hex()
    return base


# ------------------------------ demo ------------------------------
if __name__ == "__main__":
    # Paste any of your rtcp.app.data samples here to sanity check.
    sample_length9 = {
        "rtcp.version": "2",
        "rtcp.padding": "0",
        "rtcp.app.subtype": "4",
        "rtcp.pt": "204",
        "rtcp.length": "9",
        "rtcp.ssrc.identifier": "0xa33887e0",
        "rtcp.app.name": "-AV-",
        "rtcp.app.data": "a3:38:87:e0:e0:02:c3:00:00:00:00:b5:00:00:71:20:00:bf:00:38:00:ce:f2:89:7a:00:00:00"
    }
    sample_length11 = {
	  "rtcp.version": "2",
	  "rtcp.padding": "0",
	  "rtcp.app.subtype": "4",
	  "rtcp.pt": "204",
	  "rtcp.length": "11",
	  "rtcp.ssrc.identifier": "0xa33887e0",
	  "rtcp.app.name": "-AV-",
	  "rtcp.app.data": "a3:38:87:e0:e0:07:db:00:00:00:00:b5:00:00:71:20:00:cf:a2:f8:a8:eb:ce:f3:00:02:38:00:02:00:ce:f2:89:7a:00:00",
	  "rtcp.length_check": "1"
    }
    
    sample = parse_avaya_rtcp_subtype4(
        rtcp_length=9,
        app_name="-AV-",
        app_data_hex="a3:38:87:e0:e0:02:c3:00:00:00:00:b5:00:00:71:20:00:bf:00:38:00:ce:f2:89:7a:00:00:00",
    )
    sample = parse_avaya_rtcp_subtype4(
        rtcp_length=9,
        app_name="-AV-",
        app_data_hex="a3:38:87:e0:e0:02:c3:00:00:00:00:b5:00:00:71:20:00:bf:00:38:00:ce:f2:89:7a:00:00:00",
    )
    print(sample)
