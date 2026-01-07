#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-

"""
This module contains the SBCE object
"""
################################ BEGIN IMPORTS ################################

import json
import logging

logger = logging.getLogger(__name__)

import os
import re
import netifaces as ni
from dataclasses import dataclass
from platform import node

################################ END IMPORTS ##################################
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

if __name__ == "__main__":
    sbce = SBCE()
    print("SBCE EMS IP: {0}".format(sbce.ems_ip))
    print("SBCE Hostname: {0}".format(sbce.hostname))
    print("SBCE Version: {0}".format(sbce.version))
    print("SBCE Hardware Type: {0}".format(sbce.hw_type))
    print("SBCE Interfaces: {0}".format(sbce.ifaces))
    print("SBCE Servers: {0}".format(sbce.servers))
    print("SBCE Media Interfaces: {0}".format(sbce.media_ifaces))
