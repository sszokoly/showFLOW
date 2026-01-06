#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This module contains the SBCE object
"""
################################ BEGIN IMPORTS ################################

import sys
sys.path.append("/usr/local/ipcs/peon/venv/lib/")
import os
import re
import netifaces as ni
from platform import node

################################ END IMPORTS ##################################
################################ BEGIN SBCE ###################################

class SBCE(object):
    """Simple SBCE object"""
    SYSINFO_PATH = "/usr/local/ipcs/etc/sysinfo"

    def __init__(self):
        """Initializes SBCE instance.

        Returns:
            obj: Asbce instance
        """
        self.capture_active = False
        self._ifaces = None
        self._ems_ip = None
        self._mgmt_ip = None
        self._signaling_ifaces = None
        self._media_ifaces = None
        self._publics = None
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

        if self._hw_type is None:
            m = re.search(r"--hw-type==(?P<hw_type>\d+)", output)
            hw_type = m["hw_type"] if m else None
            self._hw_type = hw_type

        return ems_ip

    @property
    def hw_type(self):
        """str: Returns the hardware type."""
        if self._hw_type is not None:
            return self._hw_type

        m = re.search(r"HARDWARE=(.*)\n", self.sysinfo)
        hw_type = m.group(1) if m else ""
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
    def sipcc_loglevel(self):
        """str: Returns the value of 'LOG_SUB_SIPCC' for SSYNDI.

        Raises:
            RuntimeError: if the returned value is something unexpected
                          so as to stop corrupting the DB further
        """
        sqlcmd = "SELECT LOGLEVEL FROM EXECUTION_LOGLEVEL\
                  WHERE SUBSYSTEM='LOG_SUB_SIPCC'"
        value = self._exec_sql(sqlcmd)
        if not re.match("[01]{6}$", value):
            raise RuntimeError(value)
        return value

    @sipcc_loglevel.setter
    def sipcc_loglevel(self, value):
        """Setter method to set the value of 'LOG_SUB_SIPCC' for SSYNDI.

        Args:
            value (str): in a format of [01]{6}

        Returns:
            None

        Raises:
            ValueError: if value argument is unexpected, it can only
                differ from the current sipcc_loglevel value in position 3
                that is at index 2
        """
        pattern = "".join((self.sipcc_loglevel[:2], "[01]", self.sipcc_loglevel[3:]))
        if not re.match(pattern, value):
            raise ValueError(self.LOGLEVEL_ERR.format(value))
        sqlcmd = "UPDATE EXECUTION_LOGLEVEL SET LOGLEVEL='{0}'\
                  WHERE SUBSYSTEM='LOG_SUB_SIPCC'".format(value)
        _ = self._exec_sql(sqlcmd)

    def capture_start(self):
        """Turns on Debug loglevel for 'LOG_SUB_SIPCC' subsystem.

        Returns:
            bool: True if execution was successful, False otherwise
        """
        if self.mock:
            self.capture_active = True
            return True
        value = "".join((self.sipcc_loglevel[:2], "1", self.sipcc_loglevel[3:]))
        self.sipcc_loglevel = value
        if self.sipcc_loglevel == value:
            self.capture_active = True
            return True
        return False

    def capture_stop(self):
        """Turns off Debug loglevel for 'LOG_SUB_SIPCC' subsystem.

        Returns:
            bool: True if execution was successful, False otherwise
        """
        if self.mock:
            self.capture_active = False
            return True
        value = "".join((self.sipcc_loglevel[:2], "0", self.sipcc_loglevel[3:]))
        self.sipcc_loglevel = value
        if self.sipcc_loglevel == value:
            self.capture_active = False
            return True
        return False

    def showflow(self, level=9):
        """Return the result of "showflow".

        Args:
            level (int, optional): 'showflow' verbose level

        Returns:
            list: flows in list, one flow line per list item
        """
        cmd = "showflow {0} dynamic {1}".format(self.hardware, level)
        flows = self._exec_cmd(cmd)
        return [x.strip() for x in flows.splitlines()] if flows else []

    def flowstodict(self):
        """Returns the flows as dict where a key is the SBCE IP and port
        of a flow and the value is the Flow values as dictionary.

        Returns:
            dict: keys are tuples of SBCE IP and port of flows
        """
        self.lastflows = {(f["InDstIP"], f["InDstPort"]):f for f in
                          (self._flowtodict(x) for x in self.showflow())}
        self.lastflows_timestamp = datetime.now()
        return self.lastflows

    def _flowtodict(self, f):
        """Converts flow string to dict.

        Args:
            f (str): flow line from list returned by showflow

        Returns:
            dict: flow field names and values
        """
        m = self.reFlow.search(f)
        if m:
            return self._fmtflow(m.groupdict())
        return {}

    def flows(self):
        """Returns the flows as dict where a key is the SBCE IP and port
        of a flow and the value is the Flow values as namedtuple.

        Returns:
            dict: SBCE IP and port tuple as key and Flow instance as value
        """
        self.lastflows = {(f.InDstIP, f.InDstPort):f for f in
                          (self._flow(x) for x in self.showflow())}
        self.lastflows_timestamp = datetime.now()
        return self.lastflows

    def _flow(self, f):
        """Converts flow string to Flow class instance.

        Args:
            f (str): flow line from list returned by showflow

        Returns:
            Flow: Flow class instance
        """
        m = self.reFlow.search(f)
        return self.Flow(**self._fmtflow(m.groupdict())) if m else ()

    def flow(self, asbce_ip, asbce_port):
        """Combines and returns stats for flow identified by
        asbce_ip and asbce_port.

        Args:
            asbce_ip (str): SBCE audio ip address of flow
            asbce_port (str): SBCE audio RTP port of flow

        Returns:
            dict(): {<ifaceA>: Flow, <ifaceB>: Flow}
        """
        flows = self.flows()
        fwdflow = flows.get((asbce_ip, asbce_port), {})
        if fwdflow:
            revflow = flows.get((fwdflow.OutSrcIP, fwdflow.OutSrcPort), {})
            return ({fwdflow.InIf: fwdflow, revflow.InIf: revflow}
                    if revflow else {fwdflow.InIf: fwdflow})
        return {}

    @staticmethod
    def _fmtflow(flowdict, hex=False):
        """Converts hex values from flow tuple to decimal string and
        interface numbers to interface names.

        Args:
            flowdict (dict): dict returned by flowtodict
            hex (bool, optional): to convert counters from string hex to int

        Returns:
            dict: formated flowdict
        """
        for k in ("InIf", "OutIf"):
            flowdict[k] = {"0":"A1", "1":"A2", "2":"B1", "3":"B2"}.get(flowdict[k], "?")
        for k in ("InSrcPort", "InDstPort", "OutSrcPort", "OutDstPort"):
            flowdict[k] = int(flowdict[k])
        if not hex:
            for k in ("InVlan", "OutVlan", "Enc", "Dec", "Snt", "Drp", "Rx", "Rly", "Ech"):
                flowdict[k] = int(flowdict[k], 16)
        return flowdict

    def _exec_sql(self, sqlcmd):
        """Helper funtion to build SQL command.

        Args:
            sqlcmd (str): executable SQL command string

        Returns:
            str: return value of self._exec_cmd
        """
        if os.path.isdir("/var/lib/pgsql/"):
            cmd = " ".join(("psql -t -U postgres sbcedb -c \"", sqlcmd, "\""))
        else:
            cmd = " ".join(
                ("solsql -a -x onlyresults -e \"", sqlcmd, "\"",
                 "\"tcp {0} 1320\" savon savon".format(self.ems_ip))
            )
        return self._exec_cmd(cmd).strip()

    @staticmethod
    def _exec_cmd(cmd):
        """Helper method to execute the SQL command.

        Args:
            cmd (str): complete SQL client command executable from bash

        Returns:
            str: return value from database command

        Raises:
            RuntimeError: if the SQL bash command returns error
        """
        proc = Popen(shlex.split(cmd), shell=False, stdout=PIPE, stderr=PIPE)
        data, err = proc.communicate()
        if proc.returncode == 0:
            return data
        raise RuntimeError(err)

    def _restore_loglevel(self):
        """Restores SIPCC loglevel to its initial value."""
        if not self.mock:
            self.sipcc_loglevel = self.sipcc_loglevel_inital
