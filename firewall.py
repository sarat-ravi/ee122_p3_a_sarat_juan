from pox.core import core
from pox.lib.addresses import *
from pox.lib.packet import *
import re
import time
from pox.lib.recoco.recoco import Timer

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

        # list [123, 456, 789]
        self.banned_ports = self.get_banned_port_numbers()

        # list ["google", "amazon", "bing"]
        self.banned_domains_raw = self.get_banned_domains()
        self.banned_domains = [item.split(".")[-2] for item in self.banned_domains_raw]

        # dict {<ip>: [<search_string>, <search_string2>, ...]}
        self.monitored_strings = self.get_monitored_strings()

        # dict {<ip>: True}
        self.banned_ips = {}

        # dict {<connection_tuple>: <connection_info_dict>}
        self.connection_data = {}

        self.ip_to_domain = {}

        self.var_log("Banned Ports", self.banned_ports)
        self.var_log("Banned Domains", self.banned_domains)
        #self.var_log("Monitored Strings", self.monitored_strings)


    def get_search_counts_for_strings(self, search_strings, body):
        """
        returns search counts mapping the list <search_strings>
        in the body

        sample usage:
            counts = self.get_search_counts_for_strings(search_strings=["abc", "abcdef"], 
                    body="abcdefabcabcdefabcabcqweabc")

            counts >>> [6,2]
        """
        counts = [body.count(search_string) for search_string in search_strings]
        return counts

    def write_search_counts_to_file(self, ip, port, search_strings, counts):
        """
        gets ip and a list of counts corresponding to the list of 
        search_strings and appends to counts.txt file

        sample usage:
            self.write_search_counts_to_file(ip="1.2.3.4",
                    port=123,
                    search_strings=["sarat", "juan", "testing"],
                    counts=[4,5,6])
        """

        f = open("/root/pox/ext/counts.txt", "a")
        for search_string, count in zip(search_strings, counts):
            write_string = "%s,%s,%s,%s\n" %(str(ip),
                    str(port),
                    str(search_string),
                    str(count))
            f.write(write_string)

        f.flush()
        f.close()

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

    def update_connection(self, packet, reverse):
        """
        takes an connection identifier (tuple uniquely identifying connection)
        and updates the information we have on this connection so far
        """
        packet_content = self.get_packet_content(packet=packet)
        #packet_content = str(packet_content)
        connection = self.get_connection_identifier(packet=packet)

        if reverse:
            """
            switch source and destination in tuple!!
            """
            destip, destport, srcip, srcport = connection
            connection = (srcip, srcport, destip, destport)
            #log.debug("Data returned: %s" %(str(packet_content)))

        if not connection in self.connection_data:
            log.debug("!!!!!!!!Cant Update for connection %s" %(str(connection)))
            return 

        connection_info = self.connection_data[connection]
        now = time.time()

        self.connection_data[connection]["last_modified"] = now

        if reverse:
            self.connection_data[connection]["reverse_content"] += packet_content
        else:
            self.connection_data[connection]["content"] += packet_content

        log.debug("Updating connection %s at %d, added '%s'" %(str(connection), now, packet_content))

    def _handle_MonitorData(self, event, packet, reverse):
        """
        Monitoring event handler.
        Called when data passes over the connection if monitoring
        has been enabled by a prior event handler.
        """
        try:
            if reverse:
                """
                Monitor Incoming Packets
                """
                # IP bans invalid domain name responses
                #self.monitor_response(packet=packet)
                #log.debug("Monitoring Reverse")
                self.update_connection(packet=packet, reverse=reverse)
                #log.debug("Monitoring Data. Reverse = %s" %(str(reverse)))
            else:
                """
                Monitor Outgoing Packets
                """
                # IP bans invalid domain name requests
                #self.monitor_request(packet=packet)
                #log.debug("Monitoring Forward")
                self.update_connection(packet=packet, reverse=reverse)
                #log.debug("Monitoring Data. Reverse = %s" %(str(reverse)))

        except Exception, e:
            log.debug("ERROR!!!!!!!!!!!!! %s for reverse = " %(str(e), str(reverse)))

        return

    def get_packet_content(self, packet):
        """
        takes in a packet and returns the body of the packet, or
        the http content. This represents the "body" to be searched
        by the search strings
        """
        http_data = packet.payload.payload.payload
        return http_data

    def delete_idle_connection(self, connection):
        """
        takes a connection identifier, deletes 
        connection entry in self.connection_data if idle for more than
        30 seconds
        """
        try:
            connection_data = self.connection_data[connection]

            now = time.time()
            last_modified = connection_data["last_modified"]

            # if the last packet was 30 seconds ago,
            timedelta = now - last_modified
            log.debug("Delete connection %s called with timedelta %d" %(str(connection), timedelta))

            # print domain name for debugging purposes
            srcip, srcport, destip, destport = connection
            domain = ""
            if str(destip) in self.ip_to_domain:
                domain = self.ip_to_domain[str(destip)]

            # if idle more than 30 seconds,
            if timedelta >= 27:

                # delete entry
                log.debug("----------------------------------------------------------------------------------------------")
                log.debug("Deleting Connection %s because connection idle for %d seconds" %(str(connection), timedelta))
                log.debug("-----Connection Data: (%s) %s" %(str(domain), str(connection_data)))
                log.debug("----------------------------------------------------------------------------------------------")

                #f = open("/root/pox/ext/sarat.txt", "w")
                #import json
                #data = {"request": connection_data["content"],
                        #"response": connection_data["reverse_content"]}
                #js = json.dumps(data)
                #f.write(js)
                #f.close()

                # Kill the timer
                connection_data["timer"].cancel()

                return False
        except Exception, e:
            log.debug("ERROR!!!!!!!!!!!!! (delete idle conn): %s" %(str(e)))

        return True

    def setup_connection(self, connection, packet):
        """
        1. Takes a connection and a packet

        2. Inits self.connection_data, which is a dict {<connection_tuple>: <connection_info_dict>}

        """
        
        if connection in self.connection_data:
            log.debug("Connection %s is already setup" %(str(connection)))
            return

        now = time.time()

        # create timer 
        try:
            timer = Timer(30, self.delete_idle_connection, args=[connection], recurring=True)
        except Exception, e:
            log.debug("----ERROR-----: %s" %(str(e)))

        log.debug("Setting up connection %s at %d" %(str(connection), now))

        # collect connection info per connection
        connection_data = {}
        connection_data["creation_time"] = now
        connection_data["last_modified"] = now 
        connection_data["content"] = ""
        connection_data["reverse_content"] = ""
        connection_data["timer"] = timer

        self.connection_data[connection] = connection_data

        # TODO: Create a timer to nuke the dict entry above
        # NOTE: This "time" must somehow be extended based on "last_modified"

        return connection

    def _handle_ConnectionIn (self, event, flow, packet):
        """
        New connection event handler.
        You can alter what happens with the connection by altering the
        action property of the event.
        """
        try:
            connection = self.get_connection_identifier(flow=flow, packet=packet)

            dest_ip = flow.dst

            # ban requests for banned domains
            if str(dest_ip) in self.banned_ips:
                log.debug("Denied IP %s" %(str(dest_ip)))
                event.action.deny = True
                return

            # ban invalid ports
            dest_port = int(flow.dstport)
            if self.is_invalid_or_banned_port(port=dest_port):
                log.debug("Denied Connection %s because port %d is invalid" %(str(connection), dest_port)  )
                event.action.deny = True
                return

            # default behavior for every normal connection
            #log.debug("Allowed Connection %s" %(str(connection))  )
            event.action.defer = True
            #event.action.monitor_forward = True
            #event.action.monitor_backward = True
        except Exception, e:
            log.debug("!!!!!!!!!!!!!ERROR (connection in): %s" %(str(e)))

    def _handle_DeferredConnectionIn (self, event, flow, packet):
        """
        Deferred connection event handler.
        If the initial connection handler defers its decision, this
        handler will be called when the first actual payload data
        comes across the connection.
        """
        try:
            dest_ip = flow.dst
            connection = self.get_connection_identifier(flow=flow, packet=packet)
            # if dest_ip is to be monitored for search strings
            if str(dest_ip) in self.monitored_strings:
                log.debug("Monitoring Connection %s for search terms %s" %(str(connection),
                        str(self.monitored_strings[str(dest_ip)])))
                self.setup_connection(connection=connection, packet=packet) 
                self.update_connection(packet=packet, reverse=False)
                event.action.monitor_forward = True
                event.action.monitor_backward = True
                return

            # if banned domain:
            domain = self.get_domain_name_from_packet(packet=packet)
            if domain and domain in self.banned_domains:
                log.debug("Denied domain %s because its banned!!" %(str(domain)))
                event.action.deny = True
                return

            # if everything goes well,
            log.debug("Allowed Connection %s" %(str(connection))  )
            event.action.forward =True

        except Exception, e:
            log.debug("!!!!!!!!!!!!!ERROR (deferred in): %s" %(str(e)))

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

    def get_monitored_strings(self):
        """
        reads monitored-strings.txt and returns a dict
        {<ip_addr>: [<string1>, <string2>, ...]}
        """

        f = open("/root/pox/ext/monitored-strings.txt", "r")
        lines = f.readlines() 
        f.flush()
        f.close()

        monitored_strings = {}

        for line in lines:
            line = line.strip()

            ip, search_string = line.split(":")

            # init if not already
            if not ip in monitored_strings:
                monitored_strings[ip] = []

            # append to list
            monitored_strings[ip].append(search_string) 

        return monitored_strings

    def get_banned_port_numbers(self):
        """
        parses file and returns a list of banned ports
        """
        filename = "/root/pox/ext/banned-ports.txt"
        f = open(filename, 'r')
        lines = f.readlines()

        f.flush()
        f.close()

        ports = [int(line) for line in lines]
        return ports

    def get_banned_domains(self):
        """
        parses file and returns list of banned domains
        """
        filename = "/root/pox/ext/banned-domains.txt"
        f = open(filename, 'r')
        domains = f.readlines()

        f.flush()
        f.close()

        domains = [str(domain.strip()) for domain in domains] 
        return domains

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

        connection = self.get_connection_identifier(packet=packet)
        srcip, srcport, destip, destport = connection
        self.ip_to_domain[str(destip)] = domain

        return result_dict

    def get_connection_identifier(self, flow=None, packet=None):
        """
        1. Takes in either flow or packet object (flow gets first priority), and 
            Returns n-tuple that uniquely identifies a connection

        """
        connection = None

        if flow:
            connection = (str(flow.src), 
                    int(flow.srcport), 
                    str(flow.dst), 
                    int(flow.dstport))
        elif packet:
            """
            Available from TCP:
            -----------------------------------------------
            self.prev = prev
            self.srcport  = 0 # 16 bit
            self.dstport  = 0 # 16 bit
            self.seq      = 0 # 32 bit
            self.ack      = 0 # 32 bit
            self.off      = 0 # 4 bits
            self.res      = 0 # 4 bits
            self.flags    = 0 # reserved, 2 bits flags 6 bits
            self.win      = 0 # 16 bits
            self.csum     = 0 # 16 bits
            self.urg      = 0 # 16 bits
            self.tcplen   = 20 # Options?
            self.options  = []
            self.next     = b''

            Available from IP:
            -----------------------------------------------
            self.prev = prev
            self.v     = 4
            self.hl    = ipv4.MIN_LEN / 4
            self.tos   = 0
            self.iplen = ipv4.MIN_LEN
            ipv4.ip_id = (ipv4.ip_id + 1) & 0xffff
            self.id    = ipv4.ip_id
            self.flags = 0
            self.frag  = 0
            self.ttl   = 64
            self.protocol = 0
            self.csum  = 0
            self.srcip = IP_ANY
            self.dstip = IP_ANY
            self.next  = b''
            """

            ip_packet = packet.payload
            tcp_packet = ip_packet.payload

            connection = (str(ip_packet.srcip), 
                    int(tcp_packet.srcport), 
                    str(ip_packet.dstip), 
                    int(tcp_packet.dstport))

        if connection == None:
            # This means this function isn't used correctly
            raise Exception("Both packet and flow params not found")

        return connection








