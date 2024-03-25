# Copyright Internet Association of Australia 2018. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Extreme EXOS.

Read https://napalm.readthedocs.io for more information.
"""
from napalm.base.base import NetworkDriver
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.exceptions import (
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
    )

# Removed because of ImportError: cannot import name 'py23_compat' from 'napalm.base.utils'
#from napalm.base.utils import py23_compat

from netmiko import ConnectHandler, SCPConn
from napalm.base.helpers import textfsm_extractor

import logging
import os
import uuid
import tempfile
import jinja2
import re

logging.basicConfig()


class ExosDriver(NetworkDriver):
    """Napalm driver for Extreme Networks EXOS."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor.
        :param hostname:
        :param username:
        :param password:
        :param timeout:
        :param optional_args:
        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        # Netmiko possible arguments
        netmiko_argument_map = {
            "port": None,
            "verbose": False,
            "timeout": self.timeout,
            "global_delay_factor": 1,
            "use_keys": False,
            "key_file": None,
            "ssh_strict": False,
            "system_host_keys": False,
            "alt_host_keys": False,
            "alt_key_file": "",
            "ssh_config_file": None,
            "allow_agent": False,
            "keepalive": 30,
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {
            k: optional_args.get(k, v) for k, v in netmiko_argument_map.items()
        }

        self.transport = optional_args.get("transport", "ssh")
        self.port = optional_args.get("port", 22)

        self.changed = False
        self.loaded = False
        self.backup_file = ""
        self.replace = False
        self.merge_candidate = ""
        self.replace_file = ""
        self.profile = ["extreme"]

        # netmiko args
        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        # Control automatic execution of 'file prompt quiet' for file operations
        self.auto_file_prompt = optional_args.get("auto_file_prompt", True)

        # Track whether 'file prompt quiet' has been changed by NAPALM.
        self.prompt_quiet_changed = False
        # Track whether 'file prompt quiet' is known to be configured
        self.prompt_quiet_configured = None

    '''
    def __init__(self, hostname, username, password, timeout=60,
                 optional_args={}):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args

        if optional_args is None:
            optional_args = {}
    '''

    def open(self):
        """Open a connection to the device."""
        device_type = "extreme"
        if self.transport == "telnet":
            device_type = "extreme_telnet"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Implementation of NAPALM method close."""
        self.device.close()

    def is_alive(self):
        """Implementation of NAPALM method is_alive."""
        return self.device.is_alive()

    def get_config(self, retrieve='all'):

        # EXOS doesn't support candidate configuration
        # TODO: support startup configuration (saved)
        configs = {
            'startup': '',
            'running': '',
        }

        configs['running'] = self.device.send_command('show configuration')

        return configs

    def get_optics(self, interface=None):
        structured = self._get_and_parse_output(
                        'show ports transceiver information detail'
                     )
        optics = {}

        for item in structured:
            if not item['channel'] or item['channel'] == '1':  # First / only channel
                optics[item['port_number']] = {}
                optics[item['port_number']]['physical_channels'] = {}
                optics[item['port_number']]['physical_channels']['channel'] = []

            channel = {
                "index": int(item['channel']) - 1 if item['channel'] else 0,
                "state": {
                    "input_power": {
                        "instant": float(item['rx_power_dbm'].strip('*').strip('-inf') or '0.0'),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0
                    },
                    "output_power": {
                        "instant": float(item['tx_power_dbm'].strip('*').strip('-inf') or '0.0'),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0
                    },
                    "laser_bias_current": {
                        "instant": float(item['tx_current_ma'].strip('*').strip('-inf') or '0.0'),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0
                    }
                }
            }
            optics[item['port_number']]['physical_channels']['channel'].append(channel)

        return optics

    def cli(self, commands):

        output = {}

        for cmd in commands:
            cmd_output = self.device.send_command(cmd)
            output[cmd] = cmd_output

        return output

    # TODO: Get Arp Table
    def get_arp_table(self):
        pass

    def get_bgp_config(self, group=u'', neighbor=u''):
        pass

    def get_bgp_neighbors(self):
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=u''):
        pass


    def get_environment(self):
        """
        Return environment details.

        Sample output:
        {
            "cpu": {
                "0": {
                    "%usage": 18.0
                }
            },
            "fans": {
                "FAN1": {
                    "status": true
                }
            },
            "memory": {
                "available_ram": 3884224,
                "used_ram": 784552
            },
            "power": {
                "PWR1": {
                    "capacity": 600.0,
                    "output": 92.0,
                    "status": true
                }
            },
            "temperature": {
                "CPU": {
                    "is_alert": false,
                    "is_critical": false,
                    "temperature": 45.0
                }
            }
        }
        """
        environment = {}

        mem_cmd = "show memory"
        #fan_output = self.device.send_command(fan_cmd)
        #power_cmd = self.device.send_command(power_cmd)
        #temp_cmd = self.device.send_command(temp_cmd)
        #cpu_cmd = self.device.send_command(cpu_cmd)
        mem_cmd = self.device.send_command(mem_cmd)

        #environment.setdefault("fans", {})
        #for i in fan_output.split("\n"):
        #    match = re.match(r"\s+(\d+).+(Normal|Abnormal).+", i)
        #    if match:
        #        slot = match.group(1)
        #        status = True if match.group(2) == "Normal" else False
        #        environment["fans"][slot] = {"status": status}

        #environment.setdefault("power", {})
        #for i in power_cmd.split("\n"):
        #    # match = re.match(r"\s+(\d+).+(Normal|Abnormal).+", i)
        #    match = re.match(r"\s+(\d+)\s+(\w+\d+)\s+(\w+).+\s+(\w+)\s+(\d+\.\d+)", i)
        #    if match:
        #        environment["power"][f"{match.group(2)}-{match.group(1)}"] = {
        #            "capacity": float(match.group(5)),
        #            "output": None,
        #            "status": True if match.group(4) == "Supply" else False,
        #        }

        #environment.setdefault("temperature", {})
        #for i in temp_cmd.split("\n"):
        #    match = re.split("\s+", i)
        #    if len(match) == 10:
        #        if "Upper" not in match:
        #            environment["temperature"]["slot" + match[1]] = {
        #                "is_alert": False if match[4] == "Normal" else True,
        #                "is_critical": False if match[4] == "Normal" else True,
        #                "temperature": float(match[-1]),
        #            }

        environment.setdefault("memory", {})
        environment.setdefault("fans", {})
        environment.setdefault("power", {})
        environment.setdefault("temperature", {})
        environment.setdefault("cpu", {})

        # Mem
        mem_total = re.search(r"Total.*:\s(\d+)", mem_cmd)
        mem_free = re.search(r"Free.*:\s(\d+)", mem_cmd)
        if mem_total and mem_free:
            environment["memory"] = {
                "available_ram": int(mem_free.group(1)),
                "used_ram": int(mem_total.group(1)) - int(mem_free.group(1))
            }
        else:
            return False

        return environment

    # Cred to nicko170/napalm-exos
    def get_facts(self):
        commands = ['show switch', 'show version']
        result = self.cli(commands)
        show_switch = result['show switch']

        hostname = ""
        hostname_match = re.search("SysName:\s+(.*?)\n", show_switch)
        if hostname_match:
            hostname = hostname_match.group(1)

        model = ""
        model_match = re.search("System Type:\s+(.*?)\n", show_switch)
        if model_match:
            model = model_match.group(1)


        show_version = result['show version']
        serial_number = ""
        version = ""
        serial_match = re.search("Switch\s+:\s(.*?)\s(.*?)\sRev(.*?)IMG:\s(.*?)\n", show_version)
        if serial_match:
            serial_number = serial_match.group(2)
            version = serial_match.group(4)


        return {
                "hostname": hostname.strip(),
                "vendor": "Extreme Networks",
                "model": model.strip(),
                "os_version": version.strip(),
                'serial_number': serial_number.strip(),
                }

    def get_firewall_policies(self):
        pass

    # Cred to nicko170/napalm-exos
    def get_interfaces(self):
        interfaces = {}
        commands = ['show port information detail']
        result = self.cli(commands)
        show_port = result['show port information detail']
        fsm = textfsm.TextFSM(open(str(pathlib.Path(__file__).parent.absolute()) + "/templates/exos_show_port_information_detail.textfsm"))
        result = fsm.ParseText(show_port)

        for line in result:
            speed = 0
            if line[1] == '100M': speed = 100
            if line[1] == '1G': speed = 1000
            if line[1] == '10G': speed = 10000
            if line[1] == '25G': speed = 25000
            if line[1] == '40G': speed = 40000
            if line[1] == '100G': speed = 100000
            interfaces[line[0]] = {
                   'is_up': False,
                   'is_enabled': False,
                   'description': '',
                   'last_flapped': -1,
                   'speed': speed,
                   'mtu': '',
                   'mac_address': '',
                   }

        return interfaces

    def get_interfaces_counters(self):
        pass

    def get_interfaces_ip(self):
        pass

    def get_ipv6_neighbors_table(self):
        pass

    def get_lldp_neighbors(self):
        lldp_neighbors = self._get_and_parse_output(
            'show lldp neighbors')
        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface=u''):
        pass

    def get_mac_address_table(self):
        pass

    def get_network_instances(self, name=u''):
        pass

    def get_ntp_peers(self):
        pass

    def get_ntp_servers(self):
        pass

    def get_ntp_stats(self):
        pass

    def get_probes_config(self):
        pass

    def get_probes_results(self):
        pass

    def get_route_to(self, destination=u'', protocol=u''):
        pass

    def get_snmp_information(self):
        pass

    def get_users(self):
        pass

    # OSPF
    def get_ospf(self):
        ospf_config = self._get_and_parse_output(
            'show ospf')

        return self._key_textfsm_data(ospf_config, '', override_key='global')

    def get_ospf_interfaces(self):
        ospf_interfaces = self._get_and_parse_output(
            'show ospf interfaces detail')

        return self._key_textfsm_data(ospf_interfaces, 'vlan')

    def get_ospf_neighbors(self):
        ospf_neighbors = self._get_and_parse_output(
            'show ospf neighbor detail')

        return self._key_textfsm_data(ospf_neighbors, 'neighbor')

    # MPLS
    def get_mpls_interfaces(self):
        mpls_interfaces = self._get_and_parse_output(
            'show mpls interface detail')

        return self._key_textfsm_data(mpls_interfaces, 'vlan')

    # MPLS / LDP
    def get_mpls_ldp_peers(self):
        ldp_peers = self._get_and_parse_output(
            'show mpls ldp peer')

        return self._key_textfsm_data(ldp_peers, 'peer')

    # MPLS / RSVP
    def get_mpls_rsvp_neighbors(self):
        rsvp_neighbors = self._get_and_parse_output(
            'show mpls rsvp-te neighbor detail')

        return self._key_textfsm_data(rsvp_neighbors, 'neighbor_addr')

    def get_l2vpn(self, l2vpn_type=None):
        if l2vpn_type is None:
            l2vpn = self._get_and_parse_output('show l2vpn detail')
        elif l2vpn_type == "vpls":
            l2vpn = self._get_and_parse_output('show l2vpn vpls detail')
        elif l2vpn_type == "vpws":
            l2vpn = self._get_and_parse_output('show l2vpn vpws detail')

        return l2vpn

    def get_l2vpn_vpls(self):
        return self.get_l2vpn(l2vpn_type="vpls")

    def get_l2vpn_vpws(self):
        return self.get_l2vpn(l2vpn_type="vpws")

    def get_mpls_l2vpn_summary(self):
        pass

    def ping(self, destination, source=u'', ttl=255,
             timeout=2, size=100, count=5, vrf=u''):
        pass

    def traceroute(self, sdestination, source=u'', ttl=255, timeout=2,
                   vrf=u''):
        pass

    def _get_and_parse_output(self, command):
        output = self.device.send_command(command)
        # TODO: handle file not found, parse error, blank result?
        structured = textfsm_extractor(self, command.replace(' ', '_'), output)
        return structured

    def _key_textfsm_data(self, textfsm_data, key, override_key=""):
        data = {}

        for item in textfsm_data:
            new_key = ""
            if override_key:  # nasty hack for reasons
                new_key = override_key
            else:
                new_key = item[key]
                del item[key]
            data[new_key] = item
        return data

    def _create_temp_file(self, content, extension, name=None):
        # create a temp file with option name, defaults to random UUID
        # e.g. _create_temp_file(config, "pol", name="AS6500-POLICY-IN")

        tmp_dir = tempfile.gettempdir()

        if not name:
            rand_fname = str(uuid.uuid4()) + "." + extension
            filename = os.path.join(tmp_dir, rand_fname)
        else:
            filename = os.path.join(tmp_dir, name + "." + extension)

        with open(filename, 'wt') as fobj:
            fobj.write(content)
            fobj.close()

        return filename

    def _transfer_file_scp(self, source_file, destination_file):
        scp_conn = SCPConn(self.device)
        scp_conn.scp_transfer_file(source_file, destination_file)

    def load_merge_candidate(self, filename=None, config=None):
        # SCP config snippet to device.
        if filename and config:
            raise ValueError("Cannot simultaneously set file and config")

        temp_file = self._create_temp_file(config, "xsf")

        self._transfer_file_scp(filename, temp_file)

        output = self.cli(["run script " + temp_file])

        # TODO: Cleanup the random files on the device.

        return bool(output)

    def compare_config(self):
        diff = self.cli(['run script conf_diff'])
        return diff

    def commit_config(self):
        output = self.device.send_command("save\ry\r")
        return " successfully." in output

    def load_policy_template(self, policy_name, template_source, **template_vars):
        # for Extreme:
        # if template_path is None, then it loads to running config. Otherwise it assume an absolute filesystem location.
        # e.g. /usr/local/cfg

        if isinstance(template_source, py23_compat.string_types):
            # Load and render template to string.
            configuration = jinja2.Template(template_source).render(**template_vars)

            policy_file = self._create_temp_file(configuration, "pol", name=policy_name)

            # transfer to device.
            self._transfer_file_scp(policy_file, policy_name + ".pol")

            # Check the policy
            check_command = "check policy " + policy_name
            check_output = self.cli([check_command])

            if "successful" not in check_output[check_command]:
                raise ValueError
            else:
                return configuration
        else:
            raise NotImplementedError
