#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-

################################ BEGIN IMPORTS ################################

import asyncio
import ipaddress
import json
import sys
from datetime import datetime
from typing import Callable, Any, Dict, List, Tuple, Optional


################################ END IMPORTS ##################################

import logging
logger = logging.getLogger(__name__)
from dataclasses import dataclass
from typing import Optional
import ipaddress

# ----------------------------- Dataclass -----------------------------

@dataclass
class AvayaRtcpSubtype4:
    # Store as HEX STRINGS (per your requirement)
    rtcp_ssrc: str          # e.g. "0x0688c587"
    sub4_mask: str          # e.g. "0xf107db00"

    # Always present counters
    rtp_count: int
    rtp_octet_count: int

    # Optional (None if not present in this mask/layout)
    remote_ip: Optional[str] = None
    remote_rtcp_port: Optional[int] = None

    rtp_payload: Optional[int] = None
    payload_size: Optional[int] = None

    ttl: Optional[int] = None
    dscp: Optional[int] = None

    media_encryption: Optional[int] = None
    silence_suppression: Optional[int] = None

    round_trip_time: Optional[int] = None

    incoming_rtp_src_port: Optional[int] = None
    incoming_rtp_dst_port: Optional[int] = None

    # Any bytes not mapped by the layout:
    extra_hex: str = ""

    @property
    def is_session_ended(self) -> bool:
        ended_masks = {
            0xC0024300,
            0xC002C300,
            0xD102C300,
            0xD106C300,
            0xD922C300,
            0xE002C300,
            0xF102C300,
            0xF106C300,
            0xF922C300,
        }
        return int(self.sub4_mask, 16) in ended_masks


# ----------------------------- Helpers -----------------------------

def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", "").replace(" ", "").strip())


def _u8(b: bytes, off: int) -> int:
    return b[off]


def _u16_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "big")


def _u32_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "big")


def _ip4(b: bytes, off: int) -> str:
    return str(ipaddress.IPv4Address(b[off:off + 4]))


def _mark_used(used: bytearray, start: int, n: int) -> None:
    end = min(len(used), start + n)
    for i in range(start, end):
        used[i] = 1


# ----------------------------- Layout plumbing -----------------------------

Decoder = Callable[[AvayaRtcpSubtype4, bytes, bytearray], None]

def _dec_remote_ip(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.remote_ip = _ip4(b, off)
        _mark_used(used, off, 4)
    return dec

def _dec_remote_rtcp_port(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.remote_rtcp_port = _u16_be(b, off)
        _mark_used(used, off, 2)
    return dec

def _dec_rtp_payload(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.rtp_payload = _u8(b, off)
        _mark_used(used, off, 1)
    return dec

def _dec_payload_size(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.payload_size = _u8(b, off)
        _mark_used(used, off, 1)
    return dec

def _dec_ttl(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.ttl = _u8(b, off)
        _mark_used(used, off, 1)
    return dec

def _dec_dscp(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.dscp = _u8(b, off)
        _mark_used(used, off, 1)
    return dec

def _dec_media_encryption(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.media_encryption = _u8(b, off)
        _mark_used(used, off, 1)
    return dec

def _dec_silence_suppression(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.silence_suppression = _u8(b, off)
        _mark_used(used, off, 1)
    return dec

def _dec_round_trip_time_u16(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.round_trip_time = _u16_be(b, off)
        _mark_used(used, off, 2)
    return dec

def _dec_incoming_src_port(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.incoming_rtp_src_port = _u16_be(b, off)
        _mark_used(used, off, 2)
    return dec

def _dec_incoming_dst_port(off: int) -> Decoder:
    def dec(o: AvayaRtcpSubtype4, b: bytes, used: bytearray) -> None:
        o.incoming_rtp_dst_port = _u16_be(b, off)
        _mark_used(used, off, 2)
    return dec


# ----------------------------- Mask layouts -----------------------------
# NOTE: This keeps your “decode only what we know; everything else -> extra_hex” rule.
# We only changed the *0xF107DB00* offsets to match your validated sample.

MASK_DECODERS: Dict[int, List[Decoder]] = {
    0xC0024300: [
        _dec_incoming_src_port(0x14),
        _dec_incoming_dst_port(0x16),
    ],

    0xC002C300: [
        _dec_rtp_payload(0x10),
        _dec_ttl(0x11),
        _dec_dscp(0x12),
        _dec_incoming_src_port(0x14),
        _dec_incoming_dst_port(0x16),
    ],

    0xE002C300: [
        _dec_rtp_payload(0x12),
        _dec_ttl(0x13),
        _dec_dscp(0x14),
        _dec_media_encryption(0x15),
        _dec_silence_suppression(0x16),
        _dec_incoming_dst_port(0x17),
    ],

    0xC007DB00: [
        _dec_remote_ip(0x10),
        _dec_remote_rtcp_port(0x14),
        _dec_rtp_payload(0x16),
        _dec_payload_size(0x17),
        _dec_ttl(0x18),
        _dec_dscp(0x19),
        _dec_media_encryption(0x1A),
        _dec_silence_suppression(0x1B),
        _dec_incoming_src_port(0x1C),
        _dec_incoming_dst_port(0x1E),
    ],

    0xD102C300: [
        _dec_rtp_payload(0x18),
        _dec_ttl(0x19),
        _dec_dscp(0x1A),
        _dec_media_encryption(0x1B),
        _dec_silence_suppression(0x1C),
        _dec_incoming_dst_port(0x1D),
    ],

    0xD106C300: [
        _dec_remote_ip(0x16),
        _dec_remote_rtcp_port(0x1A),
        _dec_rtp_payload(0x1C),
        _dec_ttl(0x1D),
        _dec_dscp(0x1E),
        _dec_incoming_src_port(0x1F),
        _dec_incoming_dst_port(0x21),
    ],

    0xD922C300: [
        _dec_rtp_payload(0x1A),
        _dec_ttl(0x1B),
        _dec_dscp(0x1C),
        _dec_media_encryption(0x1D),
        _dec_silence_suppression(0x1E),
        _dec_incoming_dst_port(0x1F),
    ],

    0xE007DB00: [
        _dec_remote_ip(0x12),
        _dec_remote_rtcp_port(0x16),
        _dec_rtp_payload(0x18),
        _dec_payload_size(0x19),
        _dec_ttl(0x1A),
        _dec_dscp(0x1B),
        _dec_media_encryption(0x1C),
        _dec_silence_suppression(0x1D),
        _dec_incoming_src_port(0x1E),
        _dec_incoming_dst_port(0x20),
    ],

    0xF102C300: [
        _dec_incoming_src_port(0x1B),
        _dec_incoming_dst_port(0x1D),
    ],

    0xF106C300: [
        _dec_round_trip_time_u16(0x10),
        _dec_remote_ip(0x16),
        _dec_remote_rtcp_port(0x1A),
        _dec_rtp_payload(0x1C),
        _dec_ttl(0x1D),
        _dec_dscp(0x1E),
        _dec_incoming_src_port(0x1F),
        _dec_incoming_dst_port(0x21),
    ],

    # ✅ FIXED: 0xF107DB00 offsets based on your validated packet:
    # - RTT: 0x10..0x11
    # - remote_ip: 0x18..0x1B
    # - ttl/dscp/en/su: 0x20..0x23  (e.g. 38 00 02 00)
    # - incoming ports: src at 0x24..0x25, dst at 0x26..0x27 (BE)
    0xF107DB00: [
        _dec_round_trip_time_u16(0x10),
        _dec_remote_ip(0x18),
        _dec_ttl(0x20),
        _dec_dscp(0x21),
        _dec_media_encryption(0x22),
        _dec_silence_suppression(0x23),
        _dec_incoming_src_port(0x24),
        _dec_incoming_dst_port(0x26),
        # rtp_payload/payload_size/remote_rtcp_port remain None unless you later pin them down
    ],

    0xF922C300: [
        _dec_round_trip_time_u16(0x10),
        _dec_incoming_src_port(0x20),
        _dec_incoming_dst_port(0x22),
    ],

    0xD107DB00: [
        _dec_remote_ip(0x16),
        _dec_remote_rtcp_port(0x1A),
        _dec_rtp_payload(0x1C),
        _dec_payload_size(0x1D),
        _dec_ttl(0x1E),
        _dec_dscp(0x1F),
        _dec_media_encryption(0x20),
        _dec_silence_suppression(0x21),
        _dec_incoming_src_port(0x22),
        _dec_incoming_dst_port(0x24),
    ],

    0xD927DB00: [
        _dec_remote_ip(0x1C),
        _dec_remote_rtcp_port(0x20),
        _dec_rtp_payload(0x22),
        _dec_payload_size(0x23),
        _dec_ttl(0x24),
        _dec_dscp(0x25),
        _dec_media_encryption(0x26),
        _dec_silence_suppression(0x27),
        _dec_incoming_src_port(0x28),
        _dec_incoming_dst_port(0x2A),
    ],

    0xF927DB00: [
        _dec_round_trip_time_u16(0x10),
        _dec_remote_ip(0x1C),
        _dec_remote_rtcp_port(0x20),
        _dec_rtp_payload(0x22),
        _dec_payload_size(0x23),
        _dec_ttl(0x24),
        _dec_dscp(0x25),
        _dec_media_encryption(0x26),
        _dec_silence_suppression(0x27),
        _dec_incoming_src_port(0x28),
        _dec_incoming_dst_port(0x2A),
    ],
}


# ----------------------------- Parser -----------------------------

def parse_avaya_rtcp_subtype4(
    *,
    app_name: str,
    app_data_hex: str,
    strict_mask: bool = False,
) -> Optional[AvayaRtcpSubtype4]:
    """
    Mask-driven subtype-4 parser:
      - Decodes ONLY known sub4_mask layouts
      - Returns AvayaRtcpSubtype4 (dataclass) with unknown fields = None
      - Any unmapped bytes are returned in extra_hex
      - Unknown mask -> None (or raise if strict_mask=True)
    """
    if app_name != "-AV-":
        return None

    data = _hex_to_bytes(app_data_hex)
    if len(data) < 16:
        return None

    rtcp_ssrc_i = _u32_be(data, 0)
    sub4_mask_i = _u32_be(data, 4)
    rtp_count = _u32_be(data, 8)
    rtp_octets = _u32_be(data, 12)

    decoders = MASK_DECODERS.get(sub4_mask_i)
    if decoders is None:
        if strict_mask:
            raise ValueError(f"Unknown sub4_mask 0x{sub4_mask_i:08x}")
        return None

    pkt = AvayaRtcpSubtype4(
        rtcp_ssrc=f"0x{rtcp_ssrc_i:08x}",
        sub4_mask=f"0x{sub4_mask_i:08x}",
        rtp_count=rtp_count,
        rtp_octet_count=rtp_octets,
    )

    used = bytearray(len(data))
    _mark_used(used, 0, 16)

    for dec in decoders:
        try:
            dec(pkt, data, used)
        except IndexError as e:
            raise ValueError(
                f"sub4_mask 0x{sub4_mask_i:08x}: app.data too short ({len(data)} bytes) for layout"
            ) from e

    extra = bytes(data[i] for i in range(len(data)) if used[i] == 0)
    pkt.extra_hex = extra.hex()

    return pkt


class RTCPMonitor:
    """Monitor tshark output and parse packets asynchronously."""
    
    def __init__(self, on_packet_callback: Callable, interface: str = 'any', port: int = 5005):
        """
        Initialize TShark monitor.
        
        Args:
            on_packet_callback: Callback function to call with parsed packet data
            interface: Network interface to monitor (default: 'any')
            port: UDP port to monitor (default: 5005)
        """
        self.on_packet_callback = on_packet_callback
        self.interface = interface
        self.port = port
        self.process = None
    
    async def _read_stream(self, stream, callback):
        """Read from a stream line by line and call callback for each line."""
        while True:
            line = await stream.readline()
            if not line:
                break
            callback(line.decode('utf-8'))
    
    def _handle_stdout(self, line: str):
        """Handle each line from tshark stdout."""
        # Only process lines that start with '{"timestamp"' - these are packet lines
        if line.startswith('{"timestamp"'):
            self._parse_and_callback(line)
    
    def _parse_and_callback(self, line: str):
        """Parse JSON line and call the callback."""
        try:
            json_str = line.strip()
            data = json.loads(json_str)
            self.on_packet_callback(data)
        except json.JSONDecodeError as e:
            print(f"[JSON Parse Error]: {e}", file=sys.stderr)
            print(f"[Line content]: {line}", file=sys.stderr)
    
    def _handle_stderr(self, line: str):
        """Handle each line from tshark stderr."""
        if line.strip():
            print(f"[tshark stderr]: {line.rstrip()}", file=sys.stderr)
    
    async def start(self):
        """Start monitoring tshark output."""
        cmd = [
            'tshark',
            '-q',                       # be more quiet on stdout
            '-n',                       # disable all name resolutions
            '-i', self.interface,       # name or idx of interface
            '-l',                       # flush standard output after each packet
            '-T', 'ek',                 # format of text output to Elasticsearch
            '-f', f'udp port {self.port}'  # packet filter
        ]
        
        print(f"Starting tshark with command: {' '.join(cmd)}")
        print(f"Monitoring traffic on interface {self.interface}, port {self.port}")
        print("-" * 80)
        
        # Start tshark process
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Create tasks to read stdout and stderr concurrently
        await asyncio.gather(
            self._read_stream(self.process.stdout, self._handle_stdout),
            self._read_stream(self.process.stderr, self._handle_stderr)
        )
        
        # Wait for process to complete
        await self.process.wait()
        print(f"\ntshark process exited with code: {self.process.returncode}")
    
    async def stop(self):
        """Stop the tshark process."""
        if self.process:
            self.process.terminate()
            await self.process.wait()


def handle_packet(data, rtcp_pt=204, subtype=4):
    """Example packet handler."""
    for item in data.get('layers', {}).get('rtcp', {}):
        if rtcp_pt and str(rtcp_pt) != item.get('rtcp_rtcp_pt'):
            continue
        if subtype and str(subtype) != item.get('rtcp_rtcp_app_subtype'):
            continue
        timestamp = datetime.fromtimestamp(int(data.get('timestamp')[:-3]))
        ip_src = data.get('layers', {}).get('ip', {}).get('ip_ip_src')
        ip_dst = data.get('layers', {}).get('ip', {}).get('ip_ip_dst')
        rtcp_length = int(item.get('rtcp_rtcp_length'))
        rtcp_ssrc_identifier = item.get('rtcp_rtcp_ssrc_identifier')
        rtcp_app_data = item.get('rtcp_rtcp_app_data')
        output  = f'"timestamp": "{timestamp}", '
        output += f'"ip_src": "{ip_src}", "ip_dst": "{ip_dst}", '
        output += f'"rtcp_pt": "{rtcp_pt}", "rtcp_app_subtype": "{subtype}", '
        output += f'"rtcp_length": "{rtcp_length}", '
        output += f'"rtcp_ssrc_identifier": "{rtcp_ssrc_identifier}", '
        output += f'"metric_mask": "0x{rtcp_app_data.replace(":", "")[8:16]}", '
        output += f'"rtcp_app_data": "{rtcp_app_data}"'
        print("=== OUTPUT ===\n{" + output + "}")
        parsed = parse_avaya_rtcp_subtype4(
            app_name='-AV-',
            app_data_hex=rtcp_app_data,
        )
        print(f"=== PARSED ===\n{parsed}")

async def main():
    monitor = RTCPMonitor(
        on_packet_callback=handle_packet,
        interface='any',
        port=5005
    )
    try:
        await monitor.start()
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user")
        await monitor.stop()


if __name__ == "__main__":
    asyncio.run(main())