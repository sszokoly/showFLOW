import ipaddress
from typing import Any, Dict, Optional


def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", "").replace(" ", "").strip())


def _u32_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "big")


def _u16_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "big")


def _ip4(b4: bytes) -> str:
    return str(ipaddress.IPv4Address(b4))


def _is_private_ipv4(b4: bytes) -> bool:
    try:
        ip = ipaddress.IPv4Address(b4)
        return ip.is_private and not (ip.is_multicast or ip.is_loopback or ip.is_unspecified)
    except Exception:
        return False


def _expected_app_data_len_from_rtcp_length(rtcp_length_words_minus1: int) -> int:
    # RTCP bytes = (length+1)*4. APP header is 12 bytes.
    return (rtcp_length_words_minus1 + 1) * 4 - 12


def _port_views_optional(two_bytes: bytes) -> Dict[str, Optional[int]]:
    if len(two_bytes) < 2:
        return {"le": None, "be": None}
    b2 = two_bytes[:2]
    return {
        "le": int.from_bytes(b2, "little"),
        "be": int.from_bytes(b2, "big"),
    }


def _mask_looks_like_call_end(mask_be: int) -> bool:
    # Your observed call-end pattern contains 02:c3:00 in the middle.
    return (mask_be & 0x00FFFF00) == 0x0002C300


def _mask_top(mask_be: int) -> int:
    return (mask_be >> 24) & 0xFF


def parse_avaya_rtcp_subtype4(
    *,
    rtcp_length: int,
    app_name: str,
    app_data_hex: str,
    strict_length: bool = True,
    expected_incoming_rtp_src_port: Optional[int] = None,
    expected_incoming_rtp_dst_port: Optional[int] = None,
    expected_remote_rtcp_port: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Master parser for Avaya RTCP APP subtype=4 packets (PT=204, name "-AV-").

    Key change vs previous version:
      - Corrected len=40 / mask_top=0xD1 family where remote_ip starts at 0x16 and ports are BE.
    """
    if app_name != "-AV-":
        raise ValueError(f"Unexpected app_name {app_name!r}; expected '-AV-'")

    data = _hex_to_bytes(app_data_hex)

    expected_len = _expected_app_data_len_from_rtcp_length(rtcp_length)
    if strict_length and len(data) != expected_len:
        raise ValueError(
            f"app.data length {len(data)} != expected {expected_len} from rtcp.length={rtcp_length}"
        )

    # len=8 (rtcp.length=4) empty/no-stats
    if len(data) == 8:
        return {
            "rtcp_length": rtcp_length,
            "app_data_len": 8,
            "type": "len8_empty_no_stats",
            "all_zero": (data == b"\x00" * 8),
            "raw_hex": data.hex(),
        }

    if len(data) < 16:
        raise ValueError(f"Subtype-4 app.data too short/unhandled: {len(data)} bytes")

    rtcp_ssrc = _u32_be(data, 0)
    sub4_mask = _u32_be(data, 4)
    mask_top = _mask_top(sub4_mask)

    base: Dict[str, Any] = {
        "rtcp_length": rtcp_length,
        "app_data_len": len(data),
        "type": f"len{len(data)}",
        "rtcp_ssrc_be": f"0x{rtcp_ssrc:08x}",
        "sub4_mask_be": f"0x{sub4_mask:08x}",
        "mask_top": mask_top,
        "mask_call_end_like": _mask_looks_like_call_end(sub4_mask),
        "rtp_count": _u32_be(data, 8),
        "rtp_octet_count": _u32_be(data, 12),
    }

    # ---------------- len=24 (rtcp.length=8) ----------------
    if len(data) == 24:
        base["type"] = "len24_dstport_only"
        base["reserved_u32"] = _u32_be(data, 0x10)

        dst = _port_views_optional(data[0x14:0x16])
        base["incoming_rtp_dst_port_be"] = dst["be"]
        base["incoming_rtp_dst_port_le"] = dst["le"]
        base["incoming_rtp_dst_port"] = (
            expected_incoming_rtp_dst_port
            if expected_incoming_rtp_dst_port in (dst["be"], dst["le"])
            else (dst["be"] or dst["le"] or 0)
        )
        base["incoming_rtp_src_port"] = 0
        base["pad_hex"] = data[0x16:0x18].hex()
        return base

    # ---------------- len=28 (rtcp.length=9) ----------------
    if len(data) == 28:
        base["type"] = "len28_compact"
        base["round_trip_time"] = _u16_be(data, 0x10)
        base["rtp_dscp"] = data[0x12]
        base["rtp_ttl"] = data[0x13]
        base["rtp_payload"] = data[0x14]

        src = _port_views_optional(data[0x15:0x17])
        dst = _port_views_optional(data[0x17:0x19])

        base["incoming_rtp_src_port_be"] = src["be"]
        base["incoming_rtp_src_port_le"] = src["le"]
        base["incoming_rtp_dst_port_be"] = dst["be"]
        base["incoming_rtp_dst_port_le"] = dst["le"]

        base["incoming_rtp_src_port"] = (
            expected_incoming_rtp_src_port
            if expected_incoming_rtp_src_port in (src["be"], src["le"])
            else (src["be"] or src["le"] or 0)
        )
        base["incoming_rtp_dst_port"] = (
            expected_incoming_rtp_dst_port
            if expected_incoming_rtp_dst_port in (dst["be"], dst["le"])
            else (dst["be"] or dst["le"] or 0)
        )
        base["pad_hex"] = data[0x19:0x1C].hex()
        return base

    # ---------------- len=31/32 (rtcp.length=10 family) ----------------
    # (left as-is from your current master; not modifying here)
    if len(data) in (31, 32):
        base["type"] = f"len{len(data)}_len32_family_unmodified_here"
        base["tail_raw_hex"] = data[16:].hex()
        return base

    # ---------------- len=36 (rtcp.length=11) ----------------
    if len(data) == 36:
        base["type"] = "len36_remote_block_plus_codec_flags"
        base["round_trip_time"] = _u16_be(data, 0x10)
        base["remote_ip_candidate"] = _ip4(data[0x12:0x16])

        rp = _port_views_optional(data[0x16:0x18])
        base["remote_rtcp_port_candidate_be"] = rp["be"]
        base["remote_rtcp_port_candidate_le"] = rp["le"]
        base["remote_rtcp_port_candidate"] = (
            expected_remote_rtcp_port
            if expected_remote_rtcp_port in (rp["be"], rp["le"])
            else (rp["be"] or rp["le"] or 0)
        )

        base["rtp_payload"] = data[0x18]
        base["frame_or_mode_u8"] = data[0x19]
        base["rtp_ttl"] = data[0x1A]
        base["rtp_dscp"] = data[0x1B]
        base["media_encryption"] = data[0x1C]
        base["silence_suppression"] = data[0x1D]

        src = _port_views_optional(data[0x1E:0x20])
        dst = _port_views_optional(data[0x20:0x22])

        base["incoming_rtp_src_port_be"] = src["be"]
        base["incoming_rtp_src_port_le"] = src["le"]
        base["incoming_rtp_dst_port_be"] = dst["be"]
        base["incoming_rtp_dst_port_le"] = dst["le"]

        base["incoming_rtp_src_port"] = (
            expected_incoming_rtp_src_port
            if expected_incoming_rtp_src_port in (src["be"], src["le"])
            else (src["be"] or src["le"] or 0)
        )
        base["incoming_rtp_dst_port"] = (
            expected_incoming_rtp_dst_port
            if expected_incoming_rtp_dst_port in (dst["be"], dst["le"])
            else (dst["be"] or dst["le"] or 0)
        )

        base["pad_hex"] = data[0x22:0x24].hex()
        return base

    # ---------------- len=40 (rtcp.length=12) ----------------
    if len(data) == 40:
        # Detect the D1 family by:
        #   - mask_top == 0xD1
        #   - data[0x16:0x1A] looks like a private IPv4 (remote IP)
        if mask_top == 0xD1 and _is_private_ipv4(data[0x16:0x1A]):
            base["type"] = "len40_d1_family_remoteip_ports_be"

            # These three u16s line up cleanly in your sample; names still tentative.
            base["round_trip_time"] = _u16_be(data, 0x10)
            base["jitter_buf_delay"] = _u16_be(data, 0x12)
            base["max_jitter_u16_guess"] = _u16_be(data, 0x14)

            base["remote_ip"] = _ip4(data[0x16:0x1A])

            rp = _port_views_optional(data[0x1A:0x1C])
            base["remote_rtcp_port_be"] = rp["be"]
            base["remote_rtcp_port_le"] = rp["le"]
            base["remote_rtcp_port"] = (
                expected_remote_rtcp_port
                if expected_remote_rtcp_port in (rp["be"], rp["le"])
                else (rp["be"] or rp["le"] or 0)
            )

            base["rtp_payload"] = data[0x1C]
            base["payload_size_u8_guess"] = data[0x1D]  # you can rename once confirmed

            base["ttl_dscp_raw"] = data[0x1E:0x20].hex()
            base["ttl_byte"] = data[0x1E]
            base["dscp_byte"] = data[0x1F]

            base["media_encryption"] = data[0x20]
            base["silence_suppression"] = data[0x21]

            src = _port_views_optional(data[0x22:0x24])
            dst = _port_views_optional(data[0x24:0x26])

            base["incoming_rtp_src_port_be"] = src["be"]
            base["incoming_rtp_src_port_le"] = src["le"]
            base["incoming_rtp_dst_port_be"] = dst["be"]
            base["incoming_rtp_dst_port_le"] = dst["le"]

            # For this D1 family, your examples indicate BE is correct for ports.
            base["incoming_rtp_src_port"] = (
                expected_incoming_rtp_src_port
                if expected_incoming_rtp_src_port in (src["be"], src["le"])
                else (src["be"] or src["le"] or 0)
            )
            base["incoming_rtp_dst_port"] = (
                expected_incoming_rtp_dst_port
                if expected_incoming_rtp_dst_port in (dst["be"], dst["le"])
                else (dst["be"] or dst["le"] or 0)
            )

            base["pad_tail_hex"] = data[0x26:0x28].hex()
            return base

        # Otherwise, fall back to the older len40 interpretation (unconfirmed)
        base["type"] = "len40_other_unconfirmed"
        base["tail_raw_hex"] = data[16:].hex()
        return base

    # ---------------- fallback ----------------
    base["type"] = f"len{len(data)}_unknown"
    base["tail_raw_hex"] = data[16:].hex()
    return base
