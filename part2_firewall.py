from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *
import fileinput
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
    Put your initialization code here.
    """
    log.debug("Firewall initialized. Hello")
    # [dict] -> { <destination ip> : <ports> }
    self.FTP_addresses_and_ports = {}
    # [dict] -> { <source ip> : <buffer data> }
    self.buffer = {}
     # [dict] -> { <destination ip, port> : <timer> }
    self.timers = {}
    
  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    dstip = str(flow.dst)
    srcip = str(flow.src)
    srcport = int(flow.srcport)
    dstport = int(flow.dstport)
    PORT_0 = 0
    PORT_1023 = 1023
    PORT_FTP = 21
    log.debug("The port numbers in the range of 0 to 1023 are known as the well-known ports.")
    log.debug("Port 21 is the reserved port for FTP in TCP/IP networking, and is used for its control messages.")
    
    if dstport == PORT_FTP:
      log.debug("Monitor data to determine whether we are dealing with a passive FTP connection.")
      log.debug("Attempting to make a connection between address " + dstip + " and Port 21.")
      event.action.monitor_backward = True
      
    elif dstport >= PORT_0 and dstport <= PORT_1023:
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.forward = True
    else:
        if self.FTP_addresses_and_ports.has_key(dstip):
            if dstport in self.FTP_addresses_and_ports[dstip]:
              self.check_timers(dstip, dstport)
              self.FTP_addresses_and_ports[dstip].remove(dstport)
              log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
              event.action.forward = True
        else:
          log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
          event.action.deny = True

  def check_timers(self, dstip, dstport):
    if self.timers.has_key((dstip, dstport)):
       if len(self.timers[(dstip, dstport)]) == 0:
         del self.timers[(dstip, dstport)]
       else:
         self.timers[(dstip, dstport)][0].cancel()
         self.timers[(dstip, dstport)].pop(0)

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    pass

  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    data = packet.payload.payload.payload
    srcip = str(packet.payload.srcip)
    dstip = str(packet.payload.dstip)
    srcport = int(packet.payload.payload.srcport)
    dstport = int(packet.payload.payload.dstport)
    PORT_FTP = 21
    PASSIVE_MODE = str(227)
    EXTENDED_PASSIVE_MODE = str(229)
    log.debug("Consider passive mode (PASV) to  resolve the issue of the server initiating the connection to client.")
    log.debug("PASV has the FTP server return code of 227, while Extended Passive Mode (EPSV) has the return code of 229")

    if srcport == PORT_FTP:
        if "\n" in data:
            if self.buffer.has_key((srcip, dstport)):
                data = self.buffer[(srcip, dstport)] + data
            self.buffer[(srcip, dstport)] = data.split("\n")[-1]
            i = 0
            while i < (len(data.split("\n")) - 1):
                if len(data.split("\n")[i]) > 8:
                  if PASSIVE_MODE in data[:3]:
                    log.debug(data)
                    port = int((re.compile('\d+')).findall(data)[-2])*256 + int((re.compile('\d+')).findall(data)[-1])
                    self.add_to_FTP_addresses_and_ports(srcip, port)
                    log.debug("Operation concerning passive mode done.")                  
                  if EXTENDED_PASSIVE_MODE in data[:3]:
                    log.debug(data)
                    port = int(numbers[len((re.compile('\d+')).findall(data))-1])
                    self.add_to_FTP_addresses_and_ports(srcip, port)
                    log.debug("Operation concerning extended passive mode done.")                
                i+=1
        else:
          self.add_to_buffer(srcip, dstport, data)
    log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    event.action.forward = True

  def add_to_FTP_addresses_and_ports(self, srcip, port):
    if self.FTP_addresses_and_ports.has_key(srcip):
      self.FTP_addresses_and_ports[srcip].append(port)
    else:
      self.FTP_addresses_and_ports[srcip]= []
      self.FTP_addresses_and_ports[srcip].append(port)
    new_timer = Timer(10, self.delete_idle_function, args = (srcip, port))
    if self.timers.has_key((srcip, port)):
      self.timers[(srcip, port)].append(new_timer)
    else:
      self.timers[(srcip, port)] = []
      self.timers[(srcip, port)].append(new_timer)

  def add_to_buffer(self, srcip, dstport, data):
    if self.buffer.has_key((srcip, dstport)):
      self.buffer[(srcip, dstport)] = self.buffer[(srcip, dstport)] + data
    else:
      self.buffer[(srcip, dstport)] = data
    

  def delete_idle_function(self, dstip, port):
    self.check_timers(dstip, port)
    if self.FTP_addresses_and_ports.has_key(dstip):
      if port in self.ftpAddress[dstip]:
        self.FTP_addresses_and_ports[dstip].remove(port)
    log.debug("delete idle function.")
    log.debug(self.FTP_addresses_and_ports)
