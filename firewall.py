from pox.core import core
from pox.lib.addresses import *
from pox.lib.packet import *
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
    """
    Firewall class.
    Extend this to implement some firewall functionality.
    Don't change the name or anything -- the eecore component
    expects it to be firewall.Firewall.
    """
    def __init__(self):
        """
        Constructor.
        """
        log.debug("Firewall initialized. Hello")
        self.banned_ports = self.get_banned_port_numbers()
        self.banned_domains_raw = self.get_banned_domains()
        self.banned_domains = [item.split(".")[-2] for item in self.banned_domains_raw]
        self.banned_ips = {}
        self.var_log("Banned Domains", self.banned_domains)

    def monitor_request(self, packet):
        """
        decides what to do with the connection
        based on this packet's domain_name details
        """
        self.monitor_domain(packet=packet)

    def monitor_response(self, packet):
        """
        decides what to do with the connection
        based on this packet's domain_name details
        """
        self.monitor_domain(packet=packet)

    def _handle_MonitorData(self, event, packet, reverse):
        """
        Monitoring event handler.
        Called when data passes over the connection if monitoring
        has been enabled by a prior event handler.
        """
        if reverse:
            """
            Monitor Incoming Packets
            """
            #log.debug("Monitoring Reverse")
            # IP bans invalid domain name responses
            self.monitor_response(packet=packet)
        else:
            """
            Monitor Outgoing Packets
            """
            #log.debug("Monitoring Forward")
            # IP bans invalid domain name requests
            self.monitor_request(packet=packet)

        """
        Common Case Code Here: to run for both forward and reverse cases
        """
        return

    def _handle_ConnectionIn (self, event, flow, packet):
        """
        New connection event handler.
        You can alter what happens with the connection by altering the
        action property of the event.
        """
        connection = "[" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]"
        dest_ip = flow.dst

        # ban requests for banned domains
        if str(dest_ip) in self.banned_ips:
            log.debug("Denied IP %s" %(str(dest_ip)))
            event.action.deny = True
            return

        # ban invalid ports
        dest_port = int(flow.dstport)
        if self.is_invalid_or_banned_port(port=dest_port):
            log.debug("Denied Connection %s" %(str(connection))  )
            event.action.deny = True
            return

        # default behavior for every normal connection
        log.debug("Allowed Connection %s" %(str(connection))  )
        event.action.forward = True
        event.action.monitor_forward = True
        # sarat

    def is_invalid_or_banned_port(self, port):
        """
        Intelligently determines if port is banned or not
        returns True if port is banned
        """
        # obvious invalid case
        if port < 0 or port > 1023:
            return True

        # if port is banned according to banned-ports.txt
        if port in self.banned_ports:
            return True

        return False

    def _handle_DeferredConnectionIn (self, event, flow, packet):
        """
        Deferred connection event handler.
        If the initial connection handler defers its decision, this
        handler will be called when the first actual payload data
        comes across the connection.
        """
        pass

    def var_log(self, name, message, caller="ConnectionIn"):
        string = "(%s) \t %s = %s" %(str(caller),
                str(name),
                str(message))

        log.debug(str(string))

    def log_connection_data(self, event, flow, packet, caller="ConnectionIn Default"):

        # get basic connection data
        log.debug("")
        log.debug("--------------------------------------------------------------------------")


        connection = "[" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]"
        ip_packet = packet.payload
        tcp_packet = ip_packet.payload
        tcp_payload = tcp_packet.payload

        self.var_log(name="Connection", 
                message=connection, 
                caller=caller)

        self.var_log(name="TCP_Payload", 
                message=tcp_payload, 
                caller=caller)

        log.debug("--------------------------------------------------------------------------")
        log.debug("")

    def get_banned_port_numbers(self):
        """
        parses file and returns a list of banned ports
        """
        filename = "/root/pox/ext/banned-ports.txt"
        f = open(filename, 'r')
        lines = f.readlines()

        ports = [int(line) for line in lines]
        return ports

    def get_banned_domains(self):
        """
        parses file and returns list of banned domains
        """
        filename = "/root/pox/ext/banned-domains.txt"
        f = open(filename, 'r')
        domains = f.readlines()

        domains = [str(domain.strip()) for domain in domains] 
        return domains

    def unpack_ethernet_packet(self, packet):
        """
        returns ip_packet, tcp_packet, and http_data
        in that order
        """
        # gets http_data from packet
        ip_packet = packet.payload
        tcp_packet = ip_packet.payload
        http_data = tcp_packet.payload

        return ip_packet, tcp_packet, http_data

    def get_http_info(self, packet):
        """
        Parses http_data and returns useful info,
        like domain name for instance
        """
        ip_packet, tcp_packet, http_data = self.unpack_ethernet_packet(packet=packet)

        # get domain name from http header
        domain = ""
        m = re.search("(?<=Host: ).*", http_data)
        if m: domain = m.group(0).strip()

        # return misc http info
        result_dict = {}
        result_dict["domain_name"] = domain
        return result_dict

    def is_banned_domain(self, domain):
        """
        figures out if domain name is banned
        """
        if not domain:
            return False

        banned = domain in self.banned_domains
        return banned

    def get_domain_name_from_packet(self, packet):
        """
        gets domain name from http data, returns None if unparsable
        """
        # get domain name
        http_info = self.get_http_info(packet=packet)
        domain_name = http_info["domain_name"]
        hostname = None 

        # Log every nontrivial domain requested
        if not domain_name == '':
            hostname = domain_name.split(".")[-2]
            self.var_log("Domain Name", hostname)

        return hostname

    def monitor_domain(self, packet):
        """
        adds domain to naughty list when appropriate
        """
        # bans this ip as it maps to a banned domain
        domain_name = self.get_domain_name_from_packet(packet=packet)
        if self.is_banned_domain(domain=domain_name):
            ip = packet.payload.dstip
            self.banned_ips[str(ip)] = True
            log.debug("Denied Connection to %s" %(str(ip)))







