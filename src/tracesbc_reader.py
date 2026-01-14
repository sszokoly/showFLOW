#!/usr/local/ipcs/peon/venv/bin/python3

################################ BEGIN IMPORTS ################################

import asyncio
import logging

logger = logging.getLogger(__name__)

from pathlib import Path

################################ END IMPORTS ##################################
################################ BEGIN TRACESBC_READER ########################

class TraceSBCFileReader:
    """
    Async reader for rotating trace files with epoch timestamps.
    Automatically switches to newer files as they're created.
    """
    
    def __init__(
        self,
        directory: str ='/archive/log/tracesbc/tracesbc_sip',
        pattern: str = 'tracesbc_sip_[1-9][0-9][0-9]*[!_][!_]',
        check_interval: float = 0.1
    ):
        """
        Args:
            directory: Directory containing tracesbc_sip files
            pattern: Glob pattern (tracesbc_sip_[1-9][0-9][0-9]*[!_][!_])
            check_interval: How often to check for new files (seconds)
        """
        self.directory = Path(directory)
        self.pattern = pattern
        self.check_interval = check_interval
        
        self.current_file = None
        self.current_handle = None
        self.current_position = 0
    
    def _get_latest_file(self):
        """Get the most recent trace file."""
        last = max(self.directory.glob(self.pattern))
        return last if last and last.suffix != '.gz' else None
    
    async def _close_current_file(self):
        """Close the currently open file."""
        if self.current_handle:
            self.current_handle.close()
            self.current_handle = None
            self.current_position = 0
            logger.debug(f"Closed: {self.current_file.name if self.current_file else 'unknown'}")
            return self.current_handle
    
    async def _open_new_file(self, filepath):
        """Open a new trace file."""
        current_handle = await self._close_current_file()
        
        self.current_file = filepath
        self.current_handle = open(filepath, 'rb')
        if current_handle is not None:
            self.current_position = 0
        else:
            self.current_position = self.current_handle.seek(0, 2)
        
        logger.debug(f"Opened: {filepath.name}")
    
    async def _read_chunk(self, chunk_size=8192):
        """Read a chunk from current file."""
        if not self.current_handle:
            return None
        
        data = self.current_handle.read(chunk_size)
        if data:
            self.current_position += len(data)
        
        return data
    
    async def read_continuously(self, callback, chunk_size=8192):
        """
        Read trace files continuously, switching to newer files automatically.
        
        Args:
            callback: Async function to call with each chunk of data
            chunk_size: Bytes to read per iteration
        """
        try:
            while True:
                # Check for newer file
                latest_file = self._get_latest_file()
                
                if latest_file is None:
                    # No files available yet, wait
                    await asyncio.sleep(self.check_interval)
                    continue
                
                # Switch to newer file if available
                if self.current_file != latest_file:
                    await self._open_new_file(latest_file)
                
                # Read chunk from current file
                data = await self._read_chunk(chunk_size)
                
                if data:
                    # Process the data
                    await callback(data, self.current_file)
                else:
                    # No more data, wait before retrying
                    await asyncio.sleep(self.check_interval)
        
        finally:
            await self._close_current_file()
    
    async def read_message_continuously(self, callback, buffer_size=8192):
        """
        Fast message parser without regex.
        """
        message_buffer = b''
        current_message_lines = []
        
        async def process_chunk(data, filepath):
            nonlocal message_buffer, current_message_lines
            
            message_buffer += data
            lines = message_buffer.split(b'\n')
            message_buffer = lines[-1]
            
            for line in lines[:-1]:
                stripped = line.strip()
                
                # Check: at least 5 chars, all dashes
                if len(stripped) >= 5 and stripped.count(b'-') == len(stripped):
                    if current_message_lines:
                        message = b'\n'.join(current_message_lines)
                        if message.strip():
                            await callback(message, filepath)
                        current_message_lines = []
                else:
                    current_message_lines.append(line)
        
        await self.read_continuously(process_chunk, chunk_size=buffer_size)

################################ END TRACESBC_READER ##########################

if __name__ == '__main__':
    # Example usage functions
    async def process_message(line, filepath):
        """Process a single line."""
        try:
            decoded = line.decode('utf-8')
            print(f"{decoded}")
        except UnicodeDecodeError:
            print(f"[{filepath.name}] Binary data: {len(line)} bytes")
    
    # Main example
    async def main():
        reader = TraceSBCFileReader()
        await reader.read_message_continuously(process_message)

    asyncio.run(main())
