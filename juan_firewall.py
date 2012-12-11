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
    log.debug("Firewall initialized. Begin testing for Part 2.")
    self.allowed_ports = {}         # [dict] -> ( <destination ip> : <allowed ports> )
    self.timers = {}                # [dict] -> ( <<destination ip> : <allowed ports>> : <timer>)

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
      
    # [_HANDLE_CONNECTIONIN].INIT: Store the value of Source and Destination ports and ips
    srcport = flow.srcport
    dstport = flow.dstport
    srcip = flow.src
    dstiP = flow.dst
    log.debug("destination: " + str(dstip) + ", port: " + str(dstport))
    log.debug("source: " + str(srcip) + ", port: " + str(srcport))
    
    # [_HANDLE.CONNECTIONIN]::CONDITION A: If the value of the port is equal to 21, monitor
    # data to determine whether not we are dealing with a passive FTP connection.
    if int(dstport) == 21:
        if self.buffer.has_key((str(dstip), int(srcport))):
            del self.buffer[(str(dstip), int(srcport))]
        log.debug("Monitor data to determine whether we are dealing with a passive FTP connection.")
        log.debug("Attempting to make a connection between " + str(dstip) + " and Port 21.")
        event.action.monitor_backward = True
    
    # [_HANDLE.CONNECTIONIN]::CONDITION B: Considering that the value of the port is within
    # the range of 0 and 1023, allow the connection.
    elif int(dstport) >= 0 and int(flow.dstport) <= 1023:
        log.debug("Allowed connection [" + str(srcip) + ":" + str(srcport) + "," + str(dstip) + ":" + str(dstport) + "]" )
        event.action.forward = True
    
    # [_HANDLE_CONNECTIONIN]::CONDITION C: Barring the above, consider the following branches...
    else:
        # [_HANDLE_CONNECTIONIN]::CONDITION C1: In the event our dictionary for allowed
        # ports contains the given Destination IP, and the given Destination port is among
        # the values of said <destination ip : allowed_ports>-pairs...
        if self.allowed_ports.has_key(str(dstip)):
            if int(dstport) in self.allowed_ports[str(dstip)]:
                
                # [_HANDLE_CONNECTIONIN]::CONDITION C1.1: We will look into whether we have
                # the given dstip, dstport as a <dstip : dstport> key in timers. If so, look
                # at whether length of thebvalues are greater than or equal to 0.
                if self.timers.has_key((str(dstip), int(dstport))):
                    
                    # [_HANDLE_CONNECTIONIN]::CONDITION C1.1.1: If the length of the value in
                    # the kv-pair is equal to 0, delete the pair.
                    if len(self.timers[(str(dstip), int(dstport))]) == 0:
                        del self.timers[(str(dstip), int(dstport))]
    
                    # [_HANDLE_CONNECTIONIN]::CONDITION C1.1.2: If the length of the value in
                    # the kv-pair is greater than 0, terminate the execution given
                    # <dstip : dstport> and delete the pair.
                    elif len(self.timers[(str(dstip), int(dstport))]) > 0:
                        self.timers[(str(dstip), int(dstport))][0].cancel()
                        del self.timers[(str(dstip), int(dstport))] # <- CHECK IF CORRECT
    
                # Either way, remove the given destination port from allowed-port values from the
                # attached to the given dstip key in the allowed_ports dictionary. Allow the
                # connection to be established with the given port.
                self.allowed_ports[str(dstip)].remove(int(dstport))
                log.debug(self.allowed_ports)
                log.debug("An FTP connection was established with port " + str(dstport))
                event.action.forward = True
                    
        # [_HANDLE_CONNECTIONIN]::CONDITION C2: Otherwise, deny the connection.
        else:
            log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
            event.action.deny = True


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
        
    If we get the values of 227 or 229, we want to parse the packet to get the port.
        
    """
    
    # [_HANDLE_MONITORDATA].INIT: Initialize the following: Data, Source and Destination IP,
    # Source and Destination ports.
    data = packet.payload.payload.payload
    srcIP = packet.payload.srcip
    dstIP = packet.payload.dstip
    srcPort = packet.payload.payload.srcport
    dstPort = packet.payload.payload.dstport
    log.debug("data: " + str(data))
    log.debug("srcIP: " + str(srcIP))
    log.debug("dstIP: " + str(dstIP))
    log.debug("srcPort: " + str(srcPort))
    log.debug("dstPort: " + str(dstPort))
      
    # REVISING LATER.
    return
                
      
    ''' 
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
        m = re.search("227 Entered Passive Mode .*", str(data))
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
        l = re.search("229 Entering extended passive mode.*", str(data))
        
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
    '''
                
                
  def connectionDone(self, port):
      del self.allowed_ports[port]
            
  def getPortNumber(self, num1, num2):
      hex1 = hex(num1)
      hex2_raw = hex(num2)
      hex2 = hex2_raw[2:]
      hex_total = hex1 + hex2
      return int(hex_total, 16)