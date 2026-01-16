import asyncio
import argparse
import json
import sys
from dataclasses import dataclass
from typing import Optional, List

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
        '-ni', interface,  # Interface
        '-l',           # Line buffered
        '-T', 'json',   # JSON output
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
                print("=" * 80)
            else:
                print(f"\n[Warning]: No RTCP data found in packet")
        except (KeyError, AttributeError) as e:
            print(f"[Error extracting RTCP data]: {e}", file=sys.stderr)
            print(json.dumps(data, indent=2))
    
    # Create packet buffer
    #packet_buffer = JSONPacketBuffer(on_packet_callback=handle_packet)
    
    def handle_stdout(line):
        """Handle each line from tshark stdout."""
        print(line)
        #packet_buffer.process_line(line)
    
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