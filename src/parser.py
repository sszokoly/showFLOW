#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This module contains the parser for the output of ASBCE's `showflow` command.
"""
################################ BEGIN IMPORTS ################################

import re
import logging

logger = logging.getLogger(__name__)

from dataclasses import dataclass, field, fields
from typing import List

################################ END IMPORTS ##################################

################################ BEGIN PARSER #################################

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


def hex_to_dec(string: str) -> int or str:
    try:
        return int(string, 16)
    except ValueError:
        return string


@dataclass
class Flow:
    InIf: int = field(metadata={"conversion": int})
    InSrcIP: str
    InSrcPort: int = field(metadata={"conversion": int})
    InDstIP: str
    InDstPort: int = field(metadata={"conversion": int})
    OutIf: int = field(metadata={"conversion": int})
    OutSrcIP: str
    OutSrcPort: int = field(metadata={"conversion": int})
    OutDstIP: str
    OutDstPort: int = field(metadata={"conversion": int})
    InVlan: int = field(metadata={"conversion": int})
    OutVlan: int = field(metadata={"conversion": int})
    Enc: int = field(metadata={"conversion": hex_to_dec})
    Dec: int = field(metadata={"conversion": hex_to_dec})
    Snt: int = field(metadata={"conversion": hex_to_dec})
    Drp: int = field(metadata={"conversion": hex_to_dec})
    Rx: int = field(metadata={"conversion": hex_to_dec})
    Rly: int = field(metadata={"conversion": hex_to_dec})
    Ech: str

    def __post_init__(self):
        for fld in fields(self):
            if "conversion" in fld.metadata:
                value = getattr(self, fld.name)
                converted = fld.metadata["conversion"](value)
                setattr(self, fld.name, converted)

    def is_rtcp(self) -> bool:
        return self.InSrcPort % 2 == 1 and self.InDstPort % 2 == 1


def parse_showflow_310(output: str, no_rtcp: bool = True) -> List[Flow]:
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
        match = reFLOW.match(line)
        if match:
            flow = Flow(**match.groupdict())
            if not no_rtcp or not flow.is_rtcp():
                flows.append(flow)
        else:
            logger.warning(f"Line did not match expected format: {line}")
    return flows


################################ END PARSER ###################################

if __name__ == "__main__":
    line1 = "0 [10.10.48.58:2052 -> 10.10.48.192:35048] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 74356e54{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 411 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] 74356e54{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 411 sq[1] 0 sq[2] 0 OUT 3 RELAY 10.10.32.60:35058 -> 162.248.168.235:43040 mac 0:c:29:30:7d:9f -> 20:23:51:b2:7e:50 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 411 Dec 411 Snt 0 Drp 0 Rx 411 Rly 411 ECH 0"
    line2 = "3 [162.248.168.234:47294 -> 10.10.32.60:35056] DecEna DEC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] e8e97144{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7c40 sq[1] 0 sq[2] 0 EncEna ENC srtp MKlen 10 SltLen e TlkSpt 0 SSRC[0] e8e97144{0} SSRC[1] 0{0} SSRC[2] 0{0} ROC[0] 0 ROC[1] 0 ROC[2] 0 sq[0] 7c40 sq[1] 0 sq[2] 0 OUT 0 RELAY 10.10.48.192:35046 -> 10.10.48.58:2050 mac 0:c:29:30:7d:a9 -> 0:1b:4f:3f:73:e0 rtcp_echo 0 in VLAN 0 out VLAN 0 Enc 12c Dec 12c Snt 0 Drp 0 Rx 12c Rly 12c ECH 0"
    result = parse_showflow_310(f"{line1}\n{line2}")
    print(result)
