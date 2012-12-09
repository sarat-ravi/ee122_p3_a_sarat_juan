from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import Timer
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
    log.debug("Firewall initialized.")
    self.allowed_ports = {}
    self.data_sizes = {}

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    dstport = int(flow.dstport)
    dstip = flow.dst
    log.debug("destination: " + str(dstip) + ", port: " + str(dstport))
    if dstport == 21: #check if 21 first
        # event.action.forward = True <- COMMENTED OUT, TEST IF UNNECESSARY
        # event.action.monitor_forward = True <- COMMENTED OUT, TEST IF UNNECESSARY
        event.action.monitor_backward = True
    elif dstport in self.allowed_ports.keys():
        if len(self.allowed_ports[dstport]) > 2 and dstip != self.allowed_ports[dstport][2]:
            if dstport > 1023:
                event.action.deny = True
            #log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
            else:
                event.action.forward = False
        else:
            event.action.forward = True
            # event.action.monitor_forward = True <- COMMENTED OUT, TEST IF UNNECESSARY
            # event.action.monitor_backward = True <- COMMENTED OUT, TEST IF UNNECESSARY
            del self.allowed_ports[dstport]
            #log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    # REVISIONS, SEE ORIGINAL CODE BELOW:
    elif dstport > 1023:
        log.debug("A connection was blocked " + str(dstip) + " with port number " + str(dtsprt))
        event.action.deny = True
    else:
        event.action.forward = True
# ORIGINAL CODE
'''
    elif dstport <= 1023 and dstport >= 0:
        event.action.forward = True
        #log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    else:
        event.action.deny = True
        #log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
'''
    

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    """dstport = int(flow.dstport)
    if dstport == 21:
        event.action.forward = True
        log.debug("Allowed FTP connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        log.debug(str(packet.payload.payload.payload))"""
    pass
        
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    srcIP = packet.payload.srcip
    dstIP = packet.payload.dstip
    srcPort = packet.payload.payload.srcport
    dstPort = packet.payload.payload.dstport
    if not reverse:
      ip = str(dstIP)
      extPort = str(dstPort) #made this a string
      otherPort = str(srcPort)
      out = True
    else:
      ip = str(srcIP)
      extPort = str(srcPort) #and this
      otherPort = str(dstPort)
      out = False
    #log.debug(str(packet.payload.payload))
    if int(extPort) == 21:
        m = re.search("227 Entered Passive Mode .*", str(packet.payload.payload.payload))
        if m:            
            newlineraw = m.group(0)
            newline = newlineraw.replace("227 Entered Passive Mode (", "")
            newline = newline.replace(")", "")
            #log.debug(newline)
            newportraw = newline.rsplit(',')
            newport = self.getPortNumber(int(newportraw[4]), int(newportraw[5]))
            
            assigned_ip = newportraw[0] + "." + newportraw[1] + "." + newportraw[2] + "." + newportraw[3]
            
            self.allowed_ports[newport] = [Timer(10, self.connectionDone, args = (newport)), assigned_ip]  
            self.data_sizes[newport] = -1
            #log.debug("NEW ASSIGNED IP: ")  
            #log.debug(assigned_ip)        
        l = re.search("229 Entering extended passive mode.*", str(packet.payload.payload.payload))
        
        if l:            
            newlineraw = l.group(0)
            newline = newlineraw.replace("229 Entering extended passive mode (|||", "")
            newline = newline.replace("|).", "")
            
            newport = int(newline)
            
            self.allowed_ports[newport] = [Timer(10, self.connectionDone, args = (newport))] 
            self.data_sizes[newport] = -1
    else:
        #parse TCP here
        #fromPort, toPort, seqNum
        junk = str(packet.payload.payload)
        junk = junk.replace("{","")
        junks = junk.rsplit(">")
        fromPort = junks[0]
        junk = junks[1]
        junks = junk.rsplit("} seq:")
        toPort = junks[0]
        junk = junks[1]
        junks = junk.rsplit(" ack:")
        seqNum = junks[0]
        junk = junks[1]
        junks = junk.rsplit(" f:")
        ackNum = junks[0]
        if int(fromPort) == int(extPort):
            if self.data_sizes[int(extPort)] == -1:
                self.data_sizes[int(extPort)] = int(seqNum)
            elif self.data_sizes[int(extPort)] + 1000000 < int(seqNum):
                tcppacket = packet.payload.payload
                tcppacket.srcport = dstPort
                tcppacket.dstport = srcPort
                tcppacket.seq = int(ackNum)
                tcppacket.ack = int(seqNum) + 1460
                tcppacket.RST=True
                event.send(tcppacket, reverse=False)
                
                
  def connectionDone(self, port):
      del self.allowed_ports[port]
            
  def getPortNumber(self, num1, num2):
      hex1 = hex(num1)
      hex2_raw = hex(num2)
      hex2 = hex2_raw[2:]
      hex_total = hex1 + hex2
      return int(hex_total, 16)