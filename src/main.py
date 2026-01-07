#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-

"""
This is the main module for showFLOW application.
It prints FLOWs in ASBCE that have not received audio packets.
"""
################################ BEGIN IMPORTS ################################

import asyncio
import logging

logger = logging.getLogger(__name__)

import netifaces as ni
import json
import re
import os
from asyncio import Queue
from dataclasses import dataclass
from datetime import datetime
from platform import node
from typing import Any, List, Dict, Optional

################################ END IMPORTS ##################################

from sbce import SBCE
from flow_parser import parse_showflow_310

################################ BEGIN MODULES ################################


################################ END MODULES ##################################
################################ BEGIN MAIN ###################################

class CommandResult:
    """A consistent container for command output."""

    stdout: str
    stderr: str
    returncode: Optional[int]
    name: Optional[str]
    timestamp = None

    def __init__(
        self,
        stdout: str,
        stderr: str,
        returncode: Optional[int],
        name: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> None:
        """
        Initializes the CommandResult objects.
        """
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timestamp = None
        self.name = name

    def __repr__(self) -> str:
        """
        Provides a string representation for debugging and printing
        """
        fields = [
            f"name={repr(self.name)}",
            f"stdout={repr(self.stdout)}",
            f"stderr={repr(self.stderr)}",
            f"returncode={self.returncode}",
            f"timestamp={self.timestamp}",
        ]
        return f"CommandResult({', '.join(fields)})"


async def showflows(queue, sbce, level=7, sleep=2)  :
    cmd = f"showflow {sbce.hw_type} dynamic {level}"
    while True:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout_bytes, stderr_bytes = await proc.communicate()
            stdout_text = stdout_bytes.decode(errors="replace").strip()
            stderr_text = stderr_bytes.decode(errors="replace").strip()
                        
            if proc.returncode == 0 and stdout_text:
                commandresult = CommandResult(
                    stdout=stdout_text,
                    stderr=stderr_text,
                    returncode=proc.returncode,
                    timestamp=datetime.now(),
                    name=cmd
                )
                await queue.put(commandresult)
            else:
                logger.debug("No flows")
            await asyncio.sleep(sleep)
        except Exception as e:
            logger.error(f"{repr(e)}")


async def analyze_flows(queue, sbce):
    while True:
        commandresult = await queue.get()
        if commandresult.stderr:
            logger.error(f"Error in item {commandresult}")
            continue

        flows = parse_showflow_310(
            commandresult.stdout,
            timestamp=commandresult.timestamp
        )

        for flow in flows:
            if flow.Rx > 0:
                continue
            InSrcIP, InSrcPort, InDstIP, InDstPort = flow.in_leg
            InIface = sbce.ifaces.get(InDstIP, "??")
            OutSrcIP, OutSrcPort, OutDstIP, OutDstPort = flow.out_leg
            OutIface = sbce.ifaces.get(OutSrcIP, "??")
            inside = f"{InIface} {InDstIP::>15}:{InDstPort:<5} <= {InSrcPort:>5}:{InSrcIP:<15}"
            outside = f"{OutDstIP:>15}:{OutDstPort:<5} <= {OutSrcPort:>5}:{OutSrcIP:<15} {OutIface}"
            print(f"{flow.timestamp}: {outside}-SBCE-{inside}")


async def main():
    """Main function for showFLOW application."""

    sbce = SBCE()
    queue = Queue()
    analyzer = asyncio.create_task(analyze_flows(queue, sbce))
    collector = asyncio.create_task(showflows(queue, sbce))
    try:
        await asyncio.gather(analyzer, collector)
    except Exception as e:
        logger.error("Exception {e}")


################################ END MAIN #####################################

if __name__ == "__main__":
    import sys
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Application terminated by user")
    except Exception as e:
        logger.exception("Unhandled exception:")
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
    else:
        logger.info("Application exited normally")