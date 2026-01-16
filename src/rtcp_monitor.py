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


class JSONPacketBuffer:
    """Buffer lines from tshark JSON output until a complete packet is received."""
    
    def __init__(self, on_packet_callback):
        self.buffer = []
        self.started = False
        self.on_packet_callback = on_packet_callback
    
    def process_line(self, line):
        """Process a single line from tshark output."""
        # Skip the opening bracket
        if line.strip() == '[':
            self.started = True
            return
        
        # Check if this is the end of a packet (line with just comma)
        if line.strip() == ',':
            if self.buffer:
                self._parse_and_callback()
            return
        
        # Check if this is the closing bracket (end of stream)
        if line.strip() == ']':
            if self.buffer:
                self._parse_and_callback()
            return
        
        # Add line to buffer if we've started
        if self.started:
            self.buffer.append(line)
    
    def _parse_and_callback(self):
        """Parse buffered JSON and call the callback."""
        try:
            # Join all buffered lines
            json_str = ''.join(self.buffer)
            # Parse JSON
            data = json.loads(json_str)
            # Call the callback with parsed data
            self.on_packet_callback(data)
        except json.JSONDecodeError as e:
            print(f"[JSON Parse Error]: {e}", file=sys.stderr)
            print(f"[Buffer content]: {''.join(self.buffer)}", file=sys.stderr)
        finally:
            # Clear buffer for next packet
            self.buffer = []


async def read_stream(stream, callback):
    """Read from a stream line by line and call callback for each line."""
    while True:
        line = await stream.readline()
        if not line:
            break
        callback(line.decode('utf-8'))


async def monitor_tshark(interface='A1', port=5005):
    """Monitor tshark output asynchronously."""
    cmd = [
        'tshark',
        '-q',           # Quiet mode
        '-ta',          # Absolute timestamp
        '-ni', interface,  # Interface
        '-l',           # Line buffered
        '-T', 'json',   # JSON output
        '-j', 'rtcp',   # RTCP protocol filter
        '-f', f'udp port {port}'  # Capture filter
    ]
    
    print(f"Starting tshark with command: {' '.join(cmd)}")
    print(f"Monitoring RTCP traffic on interface {interface}, port {port}")
    print("-" * 80)
    
    # Start tshark process
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    def handle_packet(data):
        """Handle a complete parsed RTCP packet."""
        # Extract just the RTCP data from the nested structure
        try:
            rtcp_data = data.get('_source', {}).get('layers', {}).get('rtcp', {})
            if rtcp_data:
                print(f"\n=== RTCP Packet ===")
                
                # Try to parse as Avaya Subtype 5 packet
                avaya_packet = AvayaSubtype5Packet.parse(rtcp_data)
                if avaya_packet:
                    print(avaya_packet)
                else:
                    # Try to parse as Avaya Subtype 4 packet
                    avaya_packet = AvayaSubtype4Packet.parse(rtcp_data)
                    if avaya_packet:
                        print(avaya_packet)
                    else:
                        # Not a recognized Avaya packet, print raw RTCP data
                        print(json.dumps(rtcp_data, indent=2))
                
                print("=" * 80)
            else:
                print(f"\n[Warning]: No RTCP data found in packet")
        except (KeyError, AttributeError) as e:
            print(f"[Error extracting RTCP data]: {e}", file=sys.stderr)
            print(json.dumps(data, indent=2))
    
    # Create packet buffer
    packet_buffer = JSONPacketBuffer(on_packet_callback=handle_packet)
    
    def handle_stdout(line):
        """Handle each line from tshark stdout."""
        packet_buffer.process_line(line)
    
    def handle_stderr(line):
        """Handle each line from tshark stderr."""
        if line.strip():
            print(f"[tshark stderr]: {line.rstrip()}", file=sys.stderr)
    
    # Create tasks to read stdout and stderr concurrently
    await asyncio.gather(
        read_stream(process.stdout, handle_stdout),
        read_stream(process.stderr, handle_stderr)
    )
    
    # Wait for process to complete
    await process.wait()
    print(f"\ntshark process exited with code: {process.returncode}")


def main():
    parser = argparse.ArgumentParser(description='TShark RTCP Monitor')
    parser.add_argument('--port', type=int, default=5005,
                        help='UDP port to monitor (default: 5005)')
    parser.add_argument('--interface', '-i', type=str, default='A1',
                        help='Network interface to monitor (default: A1)')
    
    args = parser.parse_args()
    
    # Python 3.6 compatible event loop handling
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(monitor_tshark(
            interface=args.interface,
            port=args.port
        ))
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user")
    finally:
        loop.close()


if __name__ == "__main__":
    main()