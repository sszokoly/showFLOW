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
################################ BEGIN FLOW_PARSER ############################

RE_FLOW = (
    r"(?P<InIf>\d+) \[",
    r"(?P<InSrcIP>[\d+.]*):",
    r"(?P<InSrcPort>\d+) -> ",
    r"(?P<InDstIP>[\d+.]*):",
    r"(?P<InDstPort>\d+)\] .*OUT ",
    r"(?P<OutIf>\d+) RELAY ",
    r"(?P<OutSrcIP>[\d+.]*):",
    r"(?P<OutSrcPort>\d+) -> ",
    r"(?P<OutDstIP>[\d+.]*):",
    r"(?P<OutDstPort>\d+).*in VLAN ",
    r"(?P<InVlan>\w+) out VLAN ",
    r"(?P<OutVlan>\w+) Enc ",
    r"(?P<Enc>\w+) Dec ",
    r"(?P<Dec>\w+) Snt ",
    r"(?P<Snt>\w+) Drp ",
    r"(?P<Drp>\w+) Rx ",
    r"(?P<Rx>\w+) Rly ",
    r"(?P<Rly>\w+) ECH ",
    r"(?P<Ech>\w+)",
)

reFLOW = re.compile("".join(RE_FLOW))


def hex_to_dec(_str: str) -> int:
    try:
        return int(_str, 16)
    except ValueError:
        return 0


@dataclass
class Flow:
    InIf: int
    InSrcIP: str
    InSrcPort: int
    InDstIP: str
    InDstPort: int
    OutIf: int
    OutSrcIP: str
    OutSrcPort: int
    OutDstIP: str
    OutDstPort: int
    InVlan: int
    OutVlan: int
    Enc: int
    Dec: int
    Snt: int
    Drp: int
    Rx: int
    Rly: int
    Ech: str
    timestamp: datetime

    @classmethod
    def from_regex(cls, match_dict: Dict[str, str], timestamp: datetime) -> 'Flow':
        """Create Flow from regex match dict with string values."""
        return cls(
            InIf=int(match_dict['InIf']),
            InSrcIP=match_dict['InSrcIP'],
            InSrcPort=int(match_dict['InSrcPort']),
            InDstIP=match_dict['InDstIP'],
            InDstPort=int(match_dict['InDstPort']),
            OutIf=int(match_dict['OutIf']),
            OutSrcIP=match_dict['OutSrcIP'],
            OutSrcPort=int(match_dict['OutSrcPort']),
            OutDstIP=match_dict['OutDstIP'],
            OutDstPort=int(match_dict['OutDstPort']),
            InVlan=int(match_dict['InVlan']),
            OutVlan=int(match_dict['OutVlan']),
            Enc=hex_to_dec(match_dict['Enc']),
            Dec=hex_to_dec(match_dict['Dec']),
            Snt=hex_to_dec(match_dict['Snt']),
            Drp=hex_to_dec(match_dict['Drp']),
            Rx=hex_to_dec(match_dict['Rx']),
            Rly=hex_to_dec(match_dict['Rly']),
            Ech=match_dict['Ech'],
            timestamp=timestamp
        )

    def is_rtcp(self) -> bool:
        return self.InSrcPort % 2 == 1 and self.InDstPort % 2 == 1

    @property
    def in_leg(self):
        return self.InSrcIP, self.InSrcPort, self.InDstPort, self.InDstIP

    @property
    def out_leg(self):
        return self.OutSrcIP, self.OutSrcPort, self.OutDstIP, self.OutDstPort


def parse_showflow_310(output: str, timestamp: datetime, no_rtcp: bool = True) -> List[Flow]:
    """
    Parses the output of the `showflow 310 dynamic` command.

    Args:
        output (str): The output string from the command.
        no_rtcp (bool): If True, RTCP flows will be excluded.

    Returns:
        List[Flow]: A list of Flow objects containing flow information.
    """
    flows = []
    for line in output.splitlines():
        m = reFLOW.match(line)
        if m:
            flow = Flow.from_regex(m.groupdict(), timestamp)
            if not no_rtcp or not flow.is_rtcp():
                flows.append(flow)
        else:
            logger.warning(f"Line did not match expected format: {line}")
    return flows

################################ END FLOW_PARSER ##############################
################################ BEGIN SBCE ###################################

@dataclass
class Server(object):
    """SBCE Server object"""
    server_config_name: str
    server_type: str
    server_address: str


@dataclass
class MediaInterface(object):
    """SBCE Media Interface object"""
    media_name: str
    interface: str
    ip_address: str
    public_ip: str


class SBCE(object):
    """Simple SBCE object"""
    SYSINFO_PATH = "/usr/local/ipcs/etc/sysinfo"

    def __init__(self):
        """Initializes SBCE instance.

        Returns:
            obj: Asbce instance
        """
        self._ems_ip = None
        self._ifaces = None
        self._media_ifaces = None
        self._servers = None
        self._sysinfo = None
        self._version = None
        self._hostname = None
        self._hw_type = None

    @property
    def ems_ip(self):
        """str: Returns the EMS IP address."""
        if self._ems_ip is not None:
            return self._ems_ip

        output = os.popen("ps --columns 999 -f -C ssyndi").read()
        m = re.search(r"--ems-node-ip=(?P<ems_ip>\d+(?:\.\d+){3})", output)

        ems_ip = m["ems_ip"] if m else ""
        self._ems_ip = ems_ip
        return ems_ip

    @property
    def hw_type(self):
        """str: Returns the hardware type."""
        if self._hw_type is not None:
            return self._hw_type

        m = re.search(r"HARDWARE=(.*)\n", self.sysinfo)
        hw_type = int(m.group(1)) if m and m.group(1).isdigit() else None
        self._hw_type = hw_type

        return hw_type

    @property
    def ifaces(self):
        """dict: Returns the IP addresses of all interface as keys
        and interface names as values. 
        """
        if self._ifaces is not None:
            return self._ifaces

        ifaces = {
            ifaddr["addr"]: iface 
            for iface in ni.interfaces() 
            for family in [ni.AF_INET, ni.AF_INET6]
            for ifaddr in ni.ifaddresses(iface).get(family, [])
        }
        self._ifaces = ifaces
        return ifaces

    @property
    def media_ifaces(self):
        """list: Returns the media interfaces."""
        if self._media_ifaces is not None:
            return self._media_ifaces

        sql = "SELECT media_name, interface, ip_address, public_ip\
                 FROM sip_media_interface_view"
        json_res = self._exec_sql(sql)
        
        if json_res:
            try:
                media_data = json.loads(json_res)
                media_ifaces = [
                    MediaInterface(
                        media_name=entry.get("media_name", ""),
                        interface=entry.get("interface", ""),
                        ip_address=entry.get("ip_address", ""),
                        public_ip=entry.get("public_ip", "")
                    )
                    for entry in media_data
                ]
                self._media_ifaces = media_ifaces
                return media_ifaces 
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON result: {json_res} - {e}")
                self._media_ifaces = []
        return []

    @property
    def sysinfo(self):
        """str: Returns the content of the sysinfo file."""
        if self._sysinfo is not None:
            return self._sysinfo

        with open(self.SYSINFO_PATH, "r") as handle:
            self._sysinfo = handle.read()
        return self._sysinfo

    @property
    def version(self):
        """str: Returns the software version of the SBCE in short format."""
        if self._version is not None:
            return self._version

        m = re.search("VERSION=(.*)\n", self.sysinfo)
        version = m.group(1) if m else ""
        self._version = version 
        return version

    @property
    def hostname(self):
        """str: Returns hostname."""
        if self._hostname is not None:
            return self._hostname

        hostname = node()
        if hostname and hostname != "localhost":
            self._hostname = hostname
            return hostname

        m = re.search(r"ApplianceName=(.*)\n", self.sysinfo)
        hostname = m.group(1) if m else ""
        self._hostname = hostname
        return hostname

    @property
    def servers(self):
        """str: Returns the management IP address."""
        if self._servers is not None:
            return self._servers

        sql = "SELECT DISTINCT server_config_name, server_type, server_address\
                 FROM sip_server_config AS sc, sip_server_config_addresses AS sa\
                 WHERE sc.server_config_id = sa.server_config_id"
        json_res = self._exec_sql(sql)

        if json_res:
            try:
                servers_data = json.loads(json_res)
                servers = [
                    Server(
                        server_config_name=entry.get("server_config_name", ""),
                        server_type=entry.get("server_type", ""),
                        server_address=entry.get("server_address", "")
                    )
                    for entry in servers_data
                ]
                self._servers = servers
                return servers
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON result: {json_res} - {e}")
                self._servers = []
        return []

    def _exec_sql(self, sql):
        fmt = f"SELECT json_agg(row_to_json(t)) FROM ({sql}) AS t;"
        psql_cmd = f'psql -t -U postgres sbcedb -c "{fmt}"'
        try:
            command = os.popen(psql_cmd)
            output = command.read().strip()
            exit_status = command.close()
            return output if exit_status is None else ""
        except Exception as e:
            logger.error(f"Failed to execute SQL command: {psql_cmd} - {e}")
            return ""

################################# END SBCE ####################################
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
            inside = f"{InIface} {InDstIP}:{InDstPort} <= {InSrcPort}:{InSrcIP}"
            outside = f"{OutDstIP}:{OutDstPort} <= {OutSrcPort}:{OutSrcIP} {OutIface}"
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
