
import asyncio
import argparse
import json
import sys
from dataclasses import dataclass
from typing import Optional, List

"""
Avaya Sub-type 5 RTCP packet layout
+----------------+---------------+---------------+---------------+
|      Byte 1    |     Byte 2    |     Byte 3    |     Byte 4    |
+----------------+---------------+---------------+---------------+
| 0 1 2 3 4 5 6 7|8 9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1|
+----------------+---------------+---------------+---------------+
|Vers|P|Subytype |   PT=APP=204  |             Length            |byte 1-4
|                              SSRC                              |byte 5-8
|                           Name="-AV-"                          |byte 9-12
|               SSRC of the  Incoming RTP stream                 |byte 13-16
|                           Metric Mask                          |byte 17-20
|         IPv4 address of the Communications Controller          |byte 21-24
|Tracert HopCount|       IPv4 Traceroute per hop info            |byte 25-28
...
| IPv4 Traceroute per hop info (for each hop check packet length)|
...
| IPv4 Address of the last hop (IPv4 Traceroute per hop info)    |byte -12:-8
|     RTT to the Last Hop        |Outgoing Stream RTP Source Port|byte -8:-4
|  Outgoing Stream RTP Dest Port |NullTermination|NullTermination|byte -4:None
+----------------+---------------+---------------+---------------+
"""
@dataclass
class AvayaSubtype5Packet:
    """
    Avaya Sub-type 5 RTCP packet layout (bytes 13+)
    
    +----------------+---------------+---------------+---------------+
    |      Byte 1    |     Byte 2    |     Byte 3    |     Byte 4    |
    +----------------+---------------+---------------+---------------+
    | 0 1 2 3 4 5 6 7|8 9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1|
    +----------------+---------------+---------------+---------------+
    |               SSRC of the  Incoming RTP stream                 |1
    |                           Metric Mask                          |2
    |         IPv4 address of the Communications Controller          |3
    |Tracert HopCount|       IPv4 Traceroute per hop info            |4
    ...
    | IPv4 Traceroute per hop info (for each hop check packet length)|
    ...
    | IPv4 Address of the last hop (IPv4 Traceroute per hop info)    |N
    |     RTT to the Last Hop        |Outgoing Stream RTP Source Port|N+1
    |  Outgoing Stream RTP Dest Port |NullTermination|NullTermination|N+2
    +----------------+---------------+---------------+---------------+
    """
    # Header fields (from tshark parsed fields)
    version: str
    padding: str
    subtype: str
    packet_type: str
    length: str
    ssrc: str
    name: str
    
    # Parsed data fields (from rtcp.app.data)
    incoming_rtp_ssrc: str
    metric_mask: str
    comm_controller_ip: str
    traceroute_hop_count: int
    traceroute_hops: List[str]
    rtt_last_hop: int
    outgoing_rtp_src_port: int
    outgoing_rtp_dst_port: int
    
    @classmethod
    def parse(cls, rtcp_data: dict) -> Optional['AvayaSubtype5Packet']:
        """Parse RTCP data into AvayaSubtype5Packet."""
        try:
            # Check if this is subtype 5
            if rtcp_data.get('rtcp.app.subtype') != '5':
                return None
            
            # Get the app data (hex string with colons)
            app_data_hex = rtcp_data.get('rtcp.app.data', '')
            if not app_data_hex:
                return None
            
            # Convert hex string to bytes
            data_bytes = bytes.fromhex(app_data_hex.replace(':', ''))
            
            # Parse the data (starting from byte 13 of the full packet)
            # Bytes 0-3: SSRC of incoming RTP stream
            incoming_rtp_ssrc = '0x' + data_bytes[0:4].hex()
            
            # Bytes 4-7: Metric Mask
            metric_mask = '0x' + data_bytes[4:8].hex()
            
            # Bytes 8-11: IPv4 address of Communications Controller
            comm_controller_ip = f"{data_bytes[8]}.{data_bytes[9]}.{data_bytes[10]}.{data_bytes[11]}"
            
            # Byte 12: Traceroute hop count
            traceroute_hop_count = data_bytes[12]
            
            # Parse traceroute hops (variable number based on hop count)
            # Each hop is 4 bytes for IPv4 address
            traceroute_hops = []
            hop_start = 13
            for i in range(traceroute_hop_count):
                hop_end = hop_start + 4
                if hop_end <= len(data_bytes):
                    hop_ip = f"{data_bytes[hop_start]}.{data_bytes[hop_start+1]}.{data_bytes[hop_start+2]}.{data_bytes[hop_start+3]}"
                    traceroute_hops.append(hop_ip)
                    hop_start = hop_end
                else:
                    break
            
            # Fixed fields at the end (working backwards from the end)
            # RTCP packets are padded to 32-bit boundaries
            # When length is odd, there are 2 null terminator bytes
            # When length is even, there is 1 null terminator byte
            rtcp_length = int(rtcp_data.get('rtcp.length', '0'))
            null_bytes = 2 if rtcp_length % 2 == 1 else 1
            
            # Outgoing stream RTP destination port (2 bytes before null terminators)
            dst_port_end = -null_bytes
            dst_port_start = dst_port_end - 2
            outgoing_rtp_dst_port = int.from_bytes(data_bytes[dst_port_start:dst_port_end], byteorder='big')
            
            # Outgoing stream RTP source port (2 bytes before dest port)
            src_port_end = dst_port_start
            src_port_start = src_port_end - 2
            outgoing_rtp_src_port = int.from_bytes(data_bytes[src_port_start:src_port_end], byteorder='big')
            
            # RTT to last hop (2 bytes before source port)
            rtt_end = src_port_start
            rtt_start = rtt_end - 2
            rtt_last_hop = int.from_bytes(data_bytes[rtt_start:rtt_end], byteorder='big')
            
            return cls(
                version=rtcp_data.get('rtcp.version', ''),
                padding=rtcp_data.get('rtcp.padding', ''),
                subtype=rtcp_data.get('rtcp.app.subtype', ''),
                packet_type=rtcp_data.get('rtcp.pt', ''),
                length=rtcp_data.get('rtcp.length', ''),
                ssrc=rtcp_data.get('rtcp.ssrc.identifier', ''),
                name=rtcp_data.get('rtcp.app.name', ''),
                incoming_rtp_ssrc=incoming_rtp_ssrc,
                metric_mask=metric_mask,
                comm_controller_ip=comm_controller_ip,
                traceroute_hop_count=traceroute_hop_count,
                traceroute_hops=traceroute_hops,
                rtt_last_hop=rtt_last_hop,
                outgoing_rtp_src_port=outgoing_rtp_src_port,
                outgoing_rtp_dst_port=outgoing_rtp_dst_port
            )
        except (IndexError, ValueError, KeyError) as e:
            print(f"[Error parsing Avaya subtype 5 packet]: {e}", file=sys.stderr)
            return None
    
    def __str__(self):
        """Pretty print the packet."""
        hops_str = '\n    '.join([f"Hop {i+1}: {hop}" for i, hop in enumerate(self.traceroute_hops)])
        return f"""
Avaya Subtype 5 RTCP Packet:
  Header:
    Version: {self.version}
    Padding: {self.padding}
    Subtype: {self.subtype}
    Packet Type: {self.packet_type}
    Length: {self.length}
    SSRC: {self.ssrc}
    Name: {self.name}
  
  Payload:
    Incoming RTP SSRC: {self.incoming_rtp_ssrc}
    Metric Mask: {self.metric_mask}
    Comm Controller IP: {self.comm_controller_ip}
    Traceroute Hop Count: {self.traceroute_hop_count}
    {hops_str if hops_str else 'No traceroute hops'}
    RTT to Last Hop: {self.rtt_last_hop} ms
    Outgoing RTP Source Port: {self.outgoing_rtp_src_port}
    Outgoing RTP Dest Port: {self.outgoing_rtp_dst_port}
"""

if __name__ == "__main__":
    rtcp_data = {
          "rtcp.version": "2",
          "rtcp.padding": "0",
          "rtcp.app.subtype": "5",
          "rtcp.pt": "204",
          "rtcp.length": "8",
          "rtcp.ssrc.identifier": "0x83731900",
          "rtcp.app.name": "-AV-",
          "rtcp.app.data": "5b:d3:c0:09:9e:00:00:00:0a:0a:30:eb:08:00:08:04:0a:0a:30:fe:ff:ff:ff:00",
          "rtcp.length_check": "1"
        }
    rtcp_data2 = {
          "rtcp.version": "2",
          "rtcp.padding": "0",
          "rtcp.app.subtype": "5",
          "rtcp.pt": "204",
          "rtcp.length": "10",
          "rtcp.ssrc.identifier": "0x83731900",
          "rtcp.app.name": "-AV-",
          "rtcp.app.data": "5b:d3:c0:09:fe:00:00:00:0a:0a:30:eb:01:0a:0a:30:3a:00:02:08:00:08:04:0a:0a:30:fe:ff:ff:ff:00:00",
          "rtcp.length_check": "1"
        }
    avaya_packet = AvayaSubtype5Packet.parse(rtcp_data)
    print(avaya_packet)
