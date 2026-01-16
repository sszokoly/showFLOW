"""
Avaya Sub-type 4 RTCP packet layout
+----------------+---------------+---------------+---------------+
|      Byte 1    |     Byte 2    |     Byte 3    |     Byte 4    |
+----------------+---------------+---------------+---------------+
| 0 1 2 3 4 5 6 7|8 9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1|
+----------------+---------------+---------------+---------------+
|Vers|P|Subytype |   PT=APP=204  |             Length            |
|                              SSRC                              |
|                           Name="-AV-"                          |
|               SSRC of the  Incoming RTP stream                 |
|                           Metric Mask                          |
|                       Received RTP Packets                     |
|                       Received RTP Octets                      |
|        Round-Trip Time         |     Jitter Buffer Delay       |
|Largest Seq Jump|Largest SeqFall|Maximum Jitter (1st&2nd bytes) |
|Maximum Jitter (3rd & 4th bytes)|Seq Jump Instances (1st 2 bytes|
|Seq Fall Instances (2nd 2 bytes)| IPv4 of remote (1st 2 bytes)  |
| IPv4 of remote (2nd 2 bytes)   |  IPv4 RTCP port of remote     |
|RTP payload type|   Frame Size  | Time to Live  | Received DSCP |
|Media Encryption|Silence Suppres|Incoming Stream RTP source port|
| Incoming Stream RTP dest port  | Null Terminate|Null Terminaten|
+----------------+---------------+---------------+---------------+
"""
import asyncio
import argparse
import json
import sys
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class AvayaSubtype4Packet:
    """
    Avaya Sub-type 4 RTCP packet layout (bytes 13+)
    
    +----------------+---------------+---------------+---------------+
    |      Byte 1    |     Byte 2    |     Byte 3    |     Byte 4    |
    +----------------+---------------+---------------+---------------+
    | 0 1 2 3 4 5 6 7|8 9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1|
    +----------------+---------------+---------------+---------------+
    |               SSRC of the  Incoming RTP stream                 |1
    |                           Metric Mask                          |2
    |                       Received RTP Packets                     |3
    |                       Received RTP Octets                      |4
    |        Round-Trip Time         |     Jitter Buffer Delay       |5
    |Largest Seq Jump|Largest SeqFall|Maximum Jitter (1st&2nd bytes) |6
    |Maximum Jitter (3rd & 4th bytes)|Seq Jump Instances (1st 2 bytes|7
    |Seq Fall Instances (2nd 2 bytes)| IPv4 of remote (1st 2 bytes)  |8
    | IPv4 of remote (2nd 2 bytes)   |  IPv4 RTCP port of remote     |9
    |RTP payload type|   Frame Size  | Time to Live  | Received DSCP |10
    |Media Encryption|Silence Suppres|Incoming Stream RTP source port|11
    | Incoming Stream RTP dest port  | Null Terminate|Null Terminaten|12
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
    received_rtp_packets: int
    received_rtp_octets: int
    round_trip_time: int
    jitter_buffer_delay: int
    largest_seq_jump: int
    largest_seq_fall: int
    maximum_jitter: int
    seq_jump_instances: int
    seq_fall_instances: int
    remote_ipv4: str
    remote_rtcp_port: int
    rtp_payload_type: int
    frame_size: int
    time_to_live: int
    received_dscp: int
    media_encryption: int
    silence_suppression: int
    incoming_rtp_src_port: int
    incoming_rtp_dst_port: int
    
    @classmethod
    def parse(cls, rtcp_data: dict) -> Optional['AvayaSubtype4Packet']:
        """Parse RTCP data into AvayaSubtype4Packet."""
        try:
            # Check if this is subtype 4
            if rtcp_data.get('rtcp.app.subtype') != '4':
                return None
            
            # Get the app data (hex string with colons)
            app_data_hex = rtcp_data.get('rtcp.app.data', '')
            if not app_data_hex:
                return None
            
            # Convert hex string to bytes
            data_bytes = bytes.fromhex(app_data_hex.replace(':', ''))
            
            # Parse the data (starting from byte 13 of the full packet)
            # All fields are fixed positions in Subtype 4
            
            # Bytes 0-3: SSRC of incoming RTP stream
            incoming_rtp_ssrc = '0x' + data_bytes[0:4].hex()
            
            # Bytes 4-7: Metric Mask
            metric_mask = '0x' + data_bytes[4:8].hex()
            
            # Bytes 8-11: Received RTP Packets
            received_rtp_packets = int.from_bytes(data_bytes[8:12], byteorder='big')
            
            # Bytes 12-15: Received RTP Octets
            received_rtp_octets = int.from_bytes(data_bytes[12:16], byteorder='big')
            
            # Bytes 16-17: Round-Trip Time
            round_trip_time = int.from_bytes(data_bytes[16:18], byteorder='big')
            
            # Bytes 18-19: Jitter Buffer Delay
            jitter_buffer_delay = int.from_bytes(data_bytes[18:20], byteorder='big')
            
            # Byte 20: Largest Seq Jump
            largest_seq_jump = data_bytes[20]
            
            # Byte 21: Largest Seq Fall
            largest_seq_fall = data_bytes[21]
            
            # Bytes 22-25: Maximum Jitter (4 bytes)
            maximum_jitter = int.from_bytes(data_bytes[22:26], byteorder='big')
            
            # Bytes 26-27: Seq Jump Instances (first 2 bytes)
            # Bytes 28-29: Seq Fall Instances (second 2 bytes)
            seq_jump_instances = int.from_bytes(data_bytes[26:28], byteorder='big')
            seq_fall_instances = int.from_bytes(data_bytes[28:30], byteorder='big')
            
            # Bytes 30-33: IPv4 of remote
            remote_ipv4 = f"{data_bytes[30]}.{data_bytes[31]}.{data_bytes[32]}.{data_bytes[33]}"
            
            # Bytes 34-35: IPv4 RTCP port of remote
            remote_rtcp_port = int.from_bytes(data_bytes[34:36], byteorder='big')
            
            # Byte 36: RTP payload type
            rtp_payload_type = data_bytes[36]
            
            # Byte 37: Frame Size
            frame_size = data_bytes[37]
            
            # Byte 38: Time to Live
            time_to_live = data_bytes[38]
            
            # Byte 39: Received DSCP
            received_dscp = data_bytes[39]
            
            # Byte 40: Media Encryption
            media_encryption = data_bytes[40]
            
            # Byte 41: Silence Suppression
            silence_suppression = data_bytes[41]
            
            # Bytes 42-43: Incoming Stream RTP source port
            incoming_rtp_src_port = int.from_bytes(data_bytes[42:44], byteorder='big')
            
            # Bytes 44-45: Incoming Stream RTP dest port
            incoming_rtp_dst_port = int.from_bytes(data_bytes[44:46], byteorder='big')
            
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
                received_rtp_packets=received_rtp_packets,
                received_rtp_octets=received_rtp_octets,
                round_trip_time=round_trip_time,
                jitter_buffer_delay=jitter_buffer_delay,
                largest_seq_jump=largest_seq_jump,
                largest_seq_fall=largest_seq_fall,
                maximum_jitter=maximum_jitter,
                seq_jump_instances=seq_jump_instances,
                seq_fall_instances=seq_fall_instances,
                remote_ipv4=remote_ipv4,
                remote_rtcp_port=remote_rtcp_port,
                rtp_payload_type=rtp_payload_type,
                frame_size=frame_size,
                time_to_live=time_to_live,
                received_dscp=received_dscp,
                media_encryption=media_encryption,
                silence_suppression=silence_suppression,
                incoming_rtp_src_port=incoming_rtp_src_port,
                incoming_rtp_dst_port=incoming_rtp_dst_port
            )
        except (IndexError, ValueError, KeyError) as e:
            print(f"[Error parsing Avaya subtype 4 packet]: {e}", file=sys.stderr)
            return None
    
    def __str__(self):
        """Pretty print the packet."""
        return f"""
Avaya Subtype 4 RTCP Packet:
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
    Received RTP Packets: {self.received_rtp_packets}
    Received RTP Octets: {self.received_rtp_octets}
    Round-Trip Time: {self.round_trip_time} ms
    Jitter Buffer Delay: {self.jitter_buffer_delay} ms
    Largest Seq Jump: {self.largest_seq_jump}
    Largest Seq Fall: {self.largest_seq_fall}
    Maximum Jitter: {self.maximum_jitter}
    Seq Jump Instances: {self.seq_jump_instances}
    Seq Fall Instances: {self.seq_fall_instances}
    Remote IPv4: {self.remote_ipv4}
    Remote RTCP Port: {self.remote_rtcp_port}
    RTP Payload Type: {self.rtp_payload_type}
    Frame Size: {self.frame_size}
    Time to Live: {self.time_to_live}
    Received DSCP: {self.received_dscp}
    Media Encryption: {self.media_encryption}
    Silence Suppression: {self.silence_suppression}
    Incoming RTP Source Port: {self.incoming_rtp_src_port}
    Incoming RTP Dest Port: {self.incoming_rtp_dst_port}
"""
