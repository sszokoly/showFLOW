#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This module contains the parser for the output of ASBCE's `showflow` command.
"""
################################ BEGIN IMPORTS ################################

import re
import logging

logger = logging.getLogger(__name__)

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict

################################ END IMPORTS ##################################
################################ BEGIN FLOW_PARSER ############################

RE_FLOW = (
    r".*?(?P<InIf>\d+) \[",
    r".*?(?P<InSrcIP>[\d+.]*):",
    r".*?(?P<InSrcPort>\d+) -> ",
    r".*?(?P<InDstIP>[\d+.]*):",
    r".*?(?P<InDstPort>\d+)\] .*?SSRC\[0\]",
    r".*?(?P<SSRC>\w+)\{0\} .*sq\[0\]",
    r".*?(?P<Seq>\w+) .*OUT ",
    r".*?(?P<OutIf>\d+) RELAY ",
    r".*?(?P<OutSrcIP>[\d+.]*):",
    r".*?(?P<OutSrcPort>\d+) -> ",
    r".*?(?P<OutDstIP>[\d+.]*):",
    r".*?(?P<OutDstPort>\d+).*in VLAN ",
    r".*?(?P<InVlan>\w+) out VLAN ",
    r".*?(?P<OutVlan>\w+) Enc ",
    r".*?(?P<Enc>\w+) Dec ",
    r".*?(?P<Dec>\w+) Snt ",
    r".*?(?P<Snt>\w+) Drp ",
    r".*?(?P<Drp>\w+) Rx ",
    r".*?(?P<Rx>\w+) Rly ",
    r".*?(?P<Rly>\w+) ECH ",
    r".*?(?P<Ech>\w+)",
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
    SSRC: int
    Seq: int
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
    Ech: int
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
            SSRC=hex_to_dec(match_dict['SSRC']),
            Seq=hex_to_dec(match_dict['Seq']),
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
            Ech=hex_to_dec(match_dict['Ech']),
            timestamp=timestamp
        )

    def is_rtcp(self) -> bool:
        return self.InSrcPort % 2 == 1 and self.InDstPort % 2 == 1

    @property
    def in_leg(self):
        return self.InSrcIP, self.InSrcPort, self.InDstIP, self.InDstPort

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

if __name__ == "__main__":
    line1 = "0 [10.10.48.58:2052 -> 10.10.48.192:35048] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 74356e54{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 411 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 74356e54{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 411 sq[1] 0 sq[2] 0 OUT 3 RELAY 10.10.32.60:35058 -> 162.248.168.235:43040 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 411 Dec 411 Snt 0 Drp 0 Rx 411 Rly 411 ECH 0"
    line2 = "3 [162.248.168.234:47294 -> 10.10.32.60:35056] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] e8e97144{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7c40 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] e8e97144{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7c40 sq[1] 0 sq[2] 0 OUT 0 RELAY 10.10.48.192:35046 -> 10.10.48.58:2050 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 12c Dec 12c Snt 0 Drp 0 Rx 12c Rly 12c ECH 0"
    result = parse_showflow_310(f"{line1}\n{line2}", datetime.now())
    for item in result:
        print(item)
