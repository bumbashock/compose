#!/usr/bin/env python
import logging
import os
import random
import re
import subprocess


def report_error():
    pass

log = logging.getLogger(__name__)


class Network(object):
    """Provides networking functionality to docker-compose


    .. note:: to make use of this functionality, docker-compose has to be
              running with an effective uuid of 0 (root). This will be checked
              and the script will ignore these networking arguments if the
              euid is not 0.

    .. note:: the net keyword must be "manual" and will be reassigned to "none"
              after entering the service convergence loop in project.py

    This class requires the interfaces keyword for dynamic assignment of
    IP addresses within docker containers. At this time, what works is the
    following:

    - Specify a new "interfaces" keyword that provides a directive to setup
      IPv4 and IPv6 addresses per interface (using shell calls to ip)
    - Specify a new "netdef" keyword that is itself a dict-like object using
      the interface name (ie. eth0) as the key and a sub-dict that allows the
      definition of:
    -- bridge: a bridge interface that the eth interface should be attached to
    -- bridge_type: type of bridge, currently supported are: ovs (OpenVswitch)
       and br. Note: OpenVSwitch or brutils must be installed on the system
    -- vlan: the VLAN to associate the interface with on an OVS bridge,
             this is not yet implemented on the regular brutils.
    -- gateway: the gateway to configure for the interface

    Example configuration:

    postgres:
      net: manual
      interfaces: [
         eth0: 10.120.0.100/24,
         eth1: 192.168.1.1/24
      ]
      netdef: {
         eth0: {
            bridge: obr0,
            bridge_type: ovs,
            gateway: 10.120.0.1,
            vlan: 100
         },
         eth1: {
            bridge: br0,
            bridge_type: br,
            gateway: 192.168.1.254
         }
      }

      ports:
        - 5432:5432
      environment:
        PGDATA: /var/lib/postgresql/data/pgdata
      volumes:
        - /srv/postgres:/var/lib/postgresql/data:rw
      image: postgres

    Explanation of new keywords:
    interfaces: a list of mappings. Map the interface name (eth0, eth1, etc),
                with the CIDR representation of the IP address you'd like to
                assign.
    netdef: a mapping of mappings; assign the bridge, bridge type (only ovs, or
            br at the moment), the gateway and vlan (only applicable to ovs
            type) to the interface.

    Commands supported: docker-compose up, docker-compose rm
    """
    net_keywords = [
        'interfaces',
        'netdef',
        'short_id',
        'client'
        ]

    def __init__(self, networking):
        self.networking = networking

        self.ip_bin = Network.where('ip')
        if self.ip_bin is None:
            raise RuntimeError("Could not find ip binary on this system, install iproute2 package or equivalent")

    def execute_net_convergence(self):
        """Called to setup the interfaces and bridge"""
        # Get docker pid via id
        for service_net in self.iter_service_config():
            name = service_net.get('name')
            client = service_net.get('client')
            container_data = client.inspect_container(service_net.get('id'))
            self.pid = container_data.get('State').get('Pid')

            # By interface:
            if service_net.get('interfaces') is None:
                log.warning('No interfaces configured for {0}'.format(name))
                continue

            log.info('Configuring interfaces for: {0}'.format(name))

            for if_idx in range(0, len(service_net.get('interfaces'))):
                _if = service_net.get('interfaces')[if_idx]
                self.addbr(_if.get('bridge'), _if.get('bridge_type'))
                result = self.addif(_if.get('name'), _if.get('address'), service_net.get('id')[:5], if_idx)
                if result is not None:
                    (int_if, ext_if) = result
                self.addif_br(ext_if, _if.get('bridge'), _if.get('bridge_type'), _if.get('vlan'))
                self.addgw(_if.get('gateway'), _if.get('name'))
                if_idx = if_idx + 1

    def execute_net_cleanup(self):
        """Called to cleanup the interfaces and bridge"""
        for service_net in self.iter_service_config():
            if service_net.get('interfaces') is None:
                continue
            for if_idx in range(0, len(service_net.get('interfaces'))):
                _if = service_net.get('interfaces')[if_idx]
                self.rmif_br(_if.get('bridge'), _if.get('bridge_type'), service_net.get('id')[:5], if_idx)
                self.rmif(service_net.get('id')[:5], if_idx)

    @property
    def service_names(self):
        return self.networking.iterkeys()

    def iter_service_config(self):
        for service_name in self.service_names:
            service_config = self.networking.get(service_name)
            yield {
                "id": service_config.get('short_id'),
                "client": service_config.get('client'),
                "name": service_name,
                "interfaces": self.get_interfaces(service_name)
            }

    def get_interfaces(self, service_name):
        service_config = self.networking.get(service_name, {})
        interface_configs = []
        for iface in service_config.get('interfaces', {}):
            for if_name in iface.iterkeys():
                # Each netdef has a iface net name key:
                netdef = service_config.get('netdef', {}).get(if_name, None)
                if netdef is None:
                    return None
                interface_configs.append(
                    {
                        "name": if_name,
                        "address": self.get_address(service_name, if_name),
                        "bridge": self.get_bridge(service_name, if_name),
                        "bridge_type": self.get_bridge_type(service_name, if_name),
                        "gateway": self.get_gateway(service_name, if_name),
                        "vlan": self.get_vlan(service_name, if_name)
                    }
                )

        return interface_configs

    def get_address(self, service_name, if_name):
        for addr_cfg in self.networking.get(service_name, {}).get('interfaces'):
            if addr_cfg.keys()[0] == if_name:
                return addr_cfg.get(if_name)

    def get_bridge(self, service_name, if_name):
        return self.networking.get(service_name, {}).get('netdef', {}).get(if_name, {}).get('bridge', None)

    def get_bridge_type(self, service_name, if_name):
        return self.networking.get(service_name, {}).get('netdef', {}).get(if_name, {}).get('bridge_type', None)

    def get_gateway(self, service_name, if_name):
        return self.networking.get(service_name, {}).get('netdef', {}).get(if_name, {}).get('gateway', None)

    def get_vlan(self, service_name, if_name):
        return self.networking.get(service_name, {}).get('netdef', {}).get(if_name, {}).get('vlan', None)

    @staticmethod
    def keywords():
        for keyw in Network.net_keywords:
            yield keyw

    @staticmethod
    def parse_options(name, options):
        networking = {}
        for keyw in Network.keywords():
            if options.get(keyw):
                networking[name] = networking.get(name, {})
                networking[name][keyw] = options.get(keyw)

        return networking

    @staticmethod
    def validate_config(config):
        for service_name in config.iterkeys():
            for key in config.get(service_name).iterkeys():
                if key not in Network.net_keywords:
                    return False

        return True

    @staticmethod
    def run_shell(cmd):
        log.debug("Executing {0}".format(cmd))
        p = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()

        return True

    @staticmethod
    def where(exe):
        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, exe)
            if is_exe(exe_file):
                return exe_file

        return None

    def __getbr_obj(self, bridge_name, bridge_type):
        if bridge_name is None or bridge_type is None:
            return None

        if bridge_type == "br":
            return BridgeNetwork()

        elif bridge_type == "ovs":
            return OVSNetwork()

        else:
            return None

    def addbr(self, bridge_name, bridge_type):
        if bridge_name is None or bridge_type is None:
            return None

        br = self.__getbr_obj(bridge_name, bridge_type)
        if br is None:
            return None

        else:
            return br.addbr(bridge_name)

    def addif(self, svc_ifname, ip_addr, _id, if_idx):
        if svc_ifname is None or if_idx is None:
            return None

        if not Network.run_shell("mkdir -p /var/run/netns"):
            report_error()
        if not Network.run_shell("ln -s /proc/{0}/ns/net /var/run/netns/{1}".format(
                self.pid, self.pid)):
            report_error()

        ext_if = "veth{0}{1}A".format(_id[:5], if_idx)
        int_if = "veth{0}{1}B".format(_id[:5], if_idx)
        if not Network.run_shell("{0} link add {1} type veth peer name {2}".format(
                self.ip_bin, ext_if, int_if)):
            report_error()

        # Setup external and internal ifaces
        self.if_ext_up(ext_if)
        self.if_int_up(int_if, svc_ifname, ip_addr)

        return (int_if, ext_if)

    def rmif(self, _id, idx):
        ext_if = "veth{0}{1}A".format(_id, idx)

        if not Network.run_shell("{0} link del {1}".format(self.ip_bin, ext_if)):
            report_error()

    def rmif_br(self, bridge_name, bridge_type, _id, idx):
        br = self.__getbr_obj(bridge_name, bridge_type)
        if_name = "veth{0}{1}A".format(_id, idx)
        if br is None:
            return None
        else:
            return br.delif(bridge_name, if_name)

    def addif_br(self, if_name, bridge_name, bridge_type, vlan):
        if if_name is None or bridge_name is None or bridge_type is None:
            return None

        br = self.__getbr_obj(bridge_name, bridge_type)
        if br is None:
            return None
        else:
            return br.addif_br(if_name, bridge_name, vlan)

    def if_ext_up(self, if_name):
        if not Network.run_shell("{0} link set {1} up".format(self.ip_bin, if_name)):
            report_error()

    @staticmethod
    def randomMAC():
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    def if_int_up(self, if_name, ns_ifname, ip_addr):
        if not Network.run_shell("{0} link set {1} netns {2}".format(self.ip_bin, if_name, self.pid)):
            report_error()
        if not Network.run_shell("{0} netns exec {1} ip link set dev {2} name {3}".format(
                self.ip_bin, self.pid, if_name, ns_ifname)):
            report_error()
        if not Network.run_shell("{0} netns exec {1} ip link set {2} address {3}".format(
                self.ip_bin, self.pid, ns_ifname, Network.randomMAC())):
            report_error()
        if not Network.run_shell("{0} netns exec {1} ip link set {2} up".format(
                self.ip_bin, self.pid, ns_ifname)):
            report_error()
        if re.search(':', ip_addr):
            log.info("Configuring IPv6")
            ip_bin = self.ip_bin + ' -6'
        else:
            ip_bin = self.ip_bin
        if not Network.run_shell("{0} netns exec {1} ip addr add {2} dev {3}".format(
                ip_bin, self.pid, ip_addr, ns_ifname)):
            report_error()
        return True

    def addgw(self, gw_addr, if_name):
        if gw_addr is None or if_name is None:
            return None

        if not Network.run_shell("{0} netns exec {1} ip route add default via {2}".format(
                self.ip_bin, self.pid, gw_addr)):
            report_error()

        return True


class BridgeNetwork(object):
    """Provides a brutil wrapper class"""
    def __init__(self):
        # Search for binary
        self.brctl_bin = Network.where('brctl')
        if self.brctl_bin is None:
            raise RuntimeError("brctl binary not found in system; install the required package")

        self.ip_bin = Network.where('ip')
        if self.ip_bin is None:
            raise RuntimeError("ip binary not found in system; install iproute2 or equivalent")

    def showbr(self):
        proc = subprocess.Popen('brctl show'.split(' '), stdout=subprocess.PIPE)
        out = proc.communicate()

        if type(out[0]) == bytes:
            brifs = re.findall(b'([\w \d]+)\t+?([\w \.\d]+)\t+?([\w]+)\t+?([\w\d]*)', out[0])
        else:
            brifs = re.findall('([\w \d]+)\t+?([\w \.\d]+)\t+?([\w]+)\t+?([\w\d]*)', str(out[0]))

        return brifs

    def addbr(self, name):
        brifnames = [br[0] for br in self.showbr()]

        if name not in brifnames:
            if not Network.run_shell("{0} addbr {1}".format(self.brctl_bin, name)):
                report_error()

        if not Network.run_shell("{0} ip link set dev {1} up".format(self.ip_bin, name)):
            report_error()

    def addif_br(self, if_name, br_name, vlan=None):
        ifnames = []
        for br in self.showbr():
            if br[0] == br_name:
                ifnames.append(br[3])

        if if_name not in ifnames:
            if not Network.run_shell("{0} addif {1} {2}".format(self.brctl_bin, br_name, if_name)):
                report_error()

    def delif(self, br_name, if_name):
        if not Network.run_shell("{0} delif {1} {2}".format(self.brctl_bin, br_name, if_name)):
            report_error()


class OVSNetwork(object):
    """Provides a OVS (OpenVSwitch) wrapper class"""
    def __init__(self):
        # Search for binary
        self.ovsbin = Network.where('ovs-vsctl')
        if self.ovsbin is None:
            raise RuntimeError("ovs binary not found in system; install required package")

        self.ip_bin = Network.where('ip')
        if self.ip_bin is None:
            raise RuntimeError('ip binary not found in system; install iproute2 or similar')

    def addbr(self, name):
        if not Network.run_shell("{0} --may-exist add-br {1}".format(self.ovsbin,
                                                                     name)):
            report_error()

    def addif_br(self, name, br_name, vlan=None):
        if vlan:
            cmd = "{0} --may-exist add-port {1} {2} tag={3}".format(self.ovsbin,
                                                                    br_name,
                                                                    name,
                                                                    vlan)
            if not Network.run_shell(cmd):
                report_error()
        else:
            cmd = "{0} --may-exist add-port {1} {2}".format(self.ovsbin,
                                                            br_name,
                                                            name,
                                                            vlan)
            if not Network.run_shell(cmd):
                report_error()

    def delif(self, br_name, if_name):
        if not Network.run_shell("{0} del-port {1} {2}".format(self.ovsbin, br_name, if_name)):
            report_error()
