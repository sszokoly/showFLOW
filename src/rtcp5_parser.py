from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Optional


def _hex_to_bytes(s: str) -> bytes:
    # Accept "aa:bb:cc" or "aabbcc" or with spaces
    return bytes.fromhex(s.replace(":", "").replace(" ", "").strip())


def _u32_be(b: bytes, off: int) -> int:
    return struct.unpack_from("!I", b, off)[0]


def _u32_le(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u16_be(b: bytes, off: int) -> int:
    return struct.unpack_from("!H", b, off)[0]


def _ip4(b4: bytes) -> str:
    return str(ipaddress.IPv4Address(b4))


def _all_zero(b: bytes) -> bool:
    return all(x == 0 for x in b)


def _expected_app_data_len_from_rtcp_length(rtcp_length_words_minus1: int) -> int:
    """
    rtcp.length = number of 32-bit words in the RTCP packet minus 1 (includes RTCP header).
    RTCP APP fixed header is 12 bytes (v/p/subtype+pt+len + ssrc + name).
    """
    total_bytes = (rtcp_length_words_minus1 + 1) * 4
    return total_bytes - 12


def parse_avaya_rtcp_subtype5(
    *,
    rtcp_length: int,
    app_name: str,
    app_data_hex: str,
    strict_length: bool = True,
) -> Dict[str, Any]:
    """
    Parse Avaya RTCP APP subtype=5 (PT=204) payload for the variants observed in your captures.

    Common prefix in app.data (offsets within app.data):
      0x00 u32 monitored_rtp_ssrc (BE)
      0x04 u32 seq/id             (LE observed; BE raw also returned)

    Variants (after the prefix):
      D: selector-only (12 bytes total)
         + u16 selector_a, u16 selector_b

      A0: controller + selector + net/mask
         + ip4 controller_ip
         + u16 selector_a, u16 selector_b
         + ip4 net_ip, ip4 netmask
         + pad(0-3)

      E: hoplist + selector
         + u8 hop_count
         + hop_count * (ip4 hop_ip + u16 hop_metric)
         + u16 selector_a, u16 selector_b
         + pad(0-3)

      A: controller + hoplist + selector + net/mask
         + ip4 controller_ip
         + u8 hop_count
         + hop_count * (ip4 hop_ip + u16 hop_metric)
         + u16 selector_a, u16 selector_b
         + ip4 net_ip, ip4 netmask
         + pad(0-3)

      B: hoplist + final_ip
         + u8 hop_count
         + hop_count * (ip4 hop_ip + u16 hop_metric)
         + ip4 final_ip
         + pad(0-3)

      C: hoplist + two-u16 trailer
         + u8 hop_count
         + hop_count * (ip4 hop_ip + u16 hop_metric)
         + u16 trailer_a, u16 trailer_b
         + pad(0-3)
    """
    if app_name != "-AV-":
        raise ValueError(f"Unexpected app_name {app_name!r}; expected '-AV-'")

    data = _hex_to_bytes(app_data_hex)
    expected = _expected_app_data_len_from_rtcp_length(rtcp_length)

    if strict_length and len(data) != expected:
        raise ValueError(
            f"app.data length {len(data)} != expected {expected} from rtcp.length={rtcp_length}"
        )

    if len(data) < 8:
        raise ValueError(f"app.data too short: {len(data)} bytes")

    monitored_ssrc_be = _u32_be(data, 0)
    seq_id_le = _u32_le(data, 4)
    seq_id_be = _u32_be(data, 4)

    def base() -> Dict[str, Any]:
        return {
            "rtcp_length": rtcp_length,
            "app_data_len": len(data),
            "monitored_rtp_ssrc_be": f"0x{monitored_ssrc_be:08x}",
            "seq_id_le": seq_id_le,
            "seq_id_be_raw": f"0x{seq_id_be:08x}",
        }

    def parse_hops_from(offset: int) -> Optional[Dict[str, Any]]:
        if len(data) < offset + 1:
            return None
        hop_count = data[offset]
        off = offset + 1
        need = hop_count * 6
        if off + need > len(data):
            return None

        hops: List[Dict[str, Any]] = []
        for _ in range(hop_count):
            hop_ip = _ip4(data[off : off + 4])
            hop_metric = _u16_be(data, off + 4)
            hops.append({"ip": hop_ip, "metric": hop_metric})
            off += 6
        return {"hop_count": hop_count, "hops": hops, "off": off}

    # ---------------- Variant D: selector-only ----------------
    def try_d_selector_only() -> Optional[Dict[str, Any]]:
        # Exactly 12 bytes in all your examples: prefix(8) + selector(4)
        if len(data) != 12:
            return None
        selector_a = _u16_be(data, 8)
        selector_b = _u16_be(data, 10)
        out = base()
        out.update(
            {
                "type": "D_selector_only",
                "selector_a": f"0x{selector_a:04x}",
                "selector_b": f"0x{selector_b:04x}",
                "padding_bytes": 0,
            }
        )
        return out

    # ---------------- Variant A0: controller + selector + net/mask ----------------
    def try_a0_controller_selector_netmask() -> Optional[Dict[str, Any]]:
        if len(data) < 8 + 4 + 4 + 8:
            return None
        controller_ip = _ip4(data[8:12])
        off = 12
        selector_a = _u16_be(data, off)
        selector_b = _u16_be(data, off + 2)
        off += 4
        if off + 8 > len(data):
            return None
        net_ip = _ip4(data[off : off + 4])
        netmask = _ip4(data[off + 4 : off + 8])
        off += 8
        pad = data[off:]
        if len(pad) > 3 or not _all_zero(pad):
            return None

        out = base()
        out.update(
            {
                "type": "A0_controller_selector_netmask",
                "controller_ip": controller_ip,
                "selector_a": f"0x{selector_a:04x}",
                "selector_b": f"0x{selector_b:04x}",
                "net_ip": net_ip,
                "netmask": netmask,
                "padding_bytes": len(pad),
            }
        )
        return out

    # ---------------- Variant E: hoplist + selector ----------------
    def try_e_hops_selector() -> Optional[Dict[str, Any]]:
        h = parse_hops_from(8)
        if not h:
            return None
        off = h["off"]
        if off + 4 > len(data):
            return None
        selector_a = _u16_be(data, off)
        selector_b = _u16_be(data, off + 2)
        off += 4
        pad = data[off:]
        if len(pad) > 3 or not _all_zero(pad):
            return None
        out = base()
        out.update(
            {
                "type": "E_hops_selector",
                "hop_count": h["hop_count"],
                "hops": h["hops"],
                "selector_a": f"0x{selector_a:04x}",
                "selector_b": f"0x{selector_b:04x}",
                "padding_bytes": len(pad),
            }
        )
        return out

    # ---------------- Variant A: controller + hoplist + selector + net/mask ----------------
    def try_a_controller_hops_selector_netmask() -> Optional[Dict[str, Any]]:
        if len(data) < 8 + 4 + 1:
            return None
        controller_ip = _ip4(data[8:12])
        hop_count = data[12]
        off = 13

        if off + hop_count * 6 > len(data):
            return None
        hops: List[Dict[str, Any]] = []
        for _ in range(hop_count):
            hop_ip = _ip4(data[off : off + 4])
            hop_metric = _u16_be(data, off + 4)
            hops.append({"ip": hop_ip, "metric": hop_metric})
            off += 6

        if off + 12 > len(data):
            return None
        selector_a = _u16_be(data, off)
        selector_b = _u16_be(data, off + 2)
        off += 4

        net_ip = _ip4(data[off : off + 4])
        netmask = _ip4(data[off + 4 : off + 8])
        off += 8

        pad = data[off:]
        if len(pad) > 3 or not _all_zero(pad):
            return None

        out = base()
        out.update(
            {
                "type": "A_controller_hops_selector_netmask",
                "controller_ip": controller_ip,
                "hop_count": hop_count,
                "hops": hops,
                "selector_a": f"0x{selector_a:04x}",
                "selector_b": f"0x{selector_b:04x}",
                "net_ip": net_ip,
                "netmask": netmask,
                "padding_bytes": len(pad),
            }
        )
        return out

    # ---------------- Variant B: hoplist + final_ip ----------------
    def try_b_hops_final_ip() -> Optional[Dict[str, Any]]:
        h = parse_hops_from(8)
        if not h:
            return None
        off = h["off"]
        if off + 4 > len(data):
            return None
        final_ip = _ip4(data[off : off + 4])
        off += 4
        pad = data[off:]
        if len(pad) > 3 or not _all_zero(pad):
            return None
        out = base()
        out.update(
            {
                "type": "B_hops_final_ip",
                "hop_count": h["hop_count"],
                "hops": h["hops"],
                "final_ip": final_ip,
                "padding_bytes": len(pad),
            }
        )
        return out

    # ---------------- Variant C: hoplist + two-u16 trailer ----------------
    def try_c_hops_two_u16_trailer() -> Optional[Dict[str, Any]]:
        h = parse_hops_from(8)
        if not h:
            return None
        off = h["off"]
        if off + 4 > len(data):
            return None
        trailer_a = _u16_be(data, off)
        trailer_b = _u16_be(data, off + 2)
        off += 4
        pad = data[off:]
        if len(pad) > 3 or not _all_zero(pad):
            return None
        out = base()
        out.update(
            {
                "type": "C_hops_two_u16_trailer",
                "hop_count": h["hop_count"],
                "hops": h["hops"],
                "trailer_u16_a": trailer_a,
                "trailer_u16_b": trailer_b,
                "trailer_u16_a_hex": f"0x{trailer_a:04x}",
                "trailer_u16_b_hex": f"0x{trailer_b:04x}",
                "padding_bytes": len(pad),
            }
        )
        return out

    # Candidate order matters. Put the most specific/diagnostic forms first.
    candidates: List[Dict[str, Any]] = []
    for fn in (
        try_d_selector_only,                # exact length==12
        try_a_controller_hops_selector_netmask,  # has controller + hop + netmask
        try_a0_controller_selector_netmask, # controller + netmask
        try_e_hops_selector,                # hoplist + selector
        try_b_hops_final_ip,                # hoplist + final ip
        try_c_hops_two_u16_trailer,         # hoplist + two u16
    ):
        r = fn()
        if r:
            candidates.append(r)

    if not candidates:
        raise ValueError("Could not match subtype-5 app.data to any known layout (A/A0/B/C/D/E)")

    # Prefer parses that include the well-known selector pair 0x0800/0x0804 when present.
    def score(c: Dict[str, Any]) -> int:
        s = 0
        t = c["type"]
        if t.startswith("A"):
            s += 30
        if t == "E_hops_selector":
            s += 20
        if t == "D_selector_only":
            s += 15
        if t == "B_hops_final_ip":
            s += 10
        if t == "C_hops_two_u16_trailer":
            s += 5
        if c.get("selector_a") == "0x0800" and c.get("selector_b") == "0x0804":
            s += 100
        return s

    return sorted(candidates, key=score, reverse=True)[0]


# ----------------------------- Demo -----------------------------
if __name__ == "__main__":
    samples = [
        # D selector-only (0x0800/0x0804)
        dict(rtcp_length=5, app_name="-AV-", app_data_hex="1a:a7:ce:4c:18:00:00:00:08:00:08:04"),
        # D selector-only (0x0800/0x0808)
        dict(rtcp_length=5, app_name="-AV-", app_data_hex="2d:a5:65:0c:18:00:00:00:08:00:08:08"),
        # A0 controller+selector+netmask (length=8)
        dict(rtcp_length=8, app_name="-AV-", app_data_hex="55:0a:b5:a8:9e:00:00:00:0a:0a:30:eb:08:00:08:04:0a:0a:30:fe:ff:ff:ff:00"),
        # A controller+hops+selector+netmask (length=10)
        dict(rtcp_length=10, app_name="-AV-", app_data_hex="55:0a:b5:a8:fe:00:00:00:0a:0a:30:eb:01:0a:0a:30:3a:00:01:08:00:08:04:0a:0a:30:fe:ff:ff:ff:00:00"),
        # E hoplist+selector (length=7)
        dict(rtcp_length=7, app_name="-AV-", app_data_hex="55:0a:b5:a8:78:00:00:00:01:0a:0a:30:3a:00:01:08:00:08:04:00"),
        # C hoplist + two u16 trailer (length=9)
        dict(rtcp_length=9, app_name="-AV-", app_data_hex="48:bd:b6:ca:78:00:00:00:02:0a:0e:32:14:00:01:0a:0e:0f:32:00:05:88:fc:55:26:00:00:00"),
    ]

    for s in samples:
        print(parse_avaya_rtcp_subtype5(**s))
