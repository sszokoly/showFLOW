#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-

################################ BEGIN IMPORTS ################################

import asyncio
import json
import sys
from typing import Callable

################################ END IMPORTS #################################

import logging
logger = logging.getLogger(__name__)

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


# Example usage (not executed when imported as module)
if __name__ == "__main__":
    def handle_packet(data):
        """Example packet handler."""
        print(f"\n=== Packet Received ===")
        print(json.dumps(data, indent=2))
        print("=" * 80)
    
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
    
    # Python 3.6 compatible event loop handling
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user")
    finally:
        loop.close()
