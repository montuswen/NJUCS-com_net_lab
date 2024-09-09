#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *

time_out=100

class Table_item:
    def __init__(self,macaddr):
        self.time=time.time()
        self.macaddr=macaddr
    def Timeout(self):
        return (time.time()-self.time)>time_out

class Table:
    def __init__(self):
        self.tab={}
    def get_item(self,key):
        if key in self.tab:
            item=self.tab[key]
            if item.Timeout():
                val=None
                self.tab.pop(key)
            else:
                val=item.macaddr
        else:
            val=None
        return val
    def add_item(self,key,mac):
        self.tab[key]=Table_item(mac)

class forward_table_item:
    def __init__(self,ip,mask,next_ip,portname):
        ipnum=IPv4Address(ip)
        masknum=IPv4Address(mask)
        self.ip=IPv4Address(int(ipnum)&int(masknum))
        self.mask=IPv4Address(masknum)
        if next_ip is not None:
            self.next_ip=IPv4Address(next_ip)
        else:
            self.next_ip=None
        self.portname=portname
        self.prefixnet=IPv4Network(str(self.ip)+'/'+mask)
    def prefixlen(self):
        return self.prefixnet.prefixlen
    def match(self,desaddr):
        return desaddr in self.prefixnet

class forward_table:
    def __init__(self,interfaces):
        self.table=[]
        f=open('forwarding_table.txt','r')
        for lines in f:
            ip,mask,desaddr,iface=lines.strip().split(' ')
            self.table.append(forward_table_item(ip,mask,desaddr,iface))
        f.close()
        for ifa in interfaces:
            self.table.append(forward_table_item(str(ifa.ipaddr),str(ifa.netmask),None,ifa.name))
    def find_match(self,desipaddr):
        maxlen=-1
        res=None
        for it in self.table:
            if(it.match(desipaddr) and it.prefixlen()>maxlen):
                res=it
                maxlen=it.prefixlen()
        return res

class queue_item:
    def __init__(self,arp,port,interface):
        self.arp=arp
        self.pkt=[]
        self.time=time.time()
        self.times=1
        self.port=port
        self.interface=interface
    def add_packet(self,pkt):
        self.pkt.append(pkt)
    def matches(self,senderaddr):
        return self.arp.get_header(Arp).targetprotoaddr==senderaddr

class queue:
    def __init__(self,net):
        self.arp_q=[]
        self.net=net
    def add_item(self,arp,pkt,port,interface):
        for item in self.arp_q:
            if item.arp.get_header(Arp).targetprotoaddr==arp.get_header(Arp).targetprotoaddr:
                item.add_packet(pkt)
                return True
        log_info("!!!")
        newitem=queue_item(arp,port,interface)
        newitem.add_packet(pkt)
        self.arp_q.append(newitem)
        self.net.send_packet(port,arp)
        return False
    def getreply(self,arp,interface):
        log_info("Reply! {}".format(arp.senderprotoaddr))
        for it in self.arp_q:
            log_info(it.arp.get_header(Arp).targetprotoaddr)
            if(it.matches(arp.senderprotoaddr)):
                for pkt in it.pkt:
                    pkt[0].dst=arp.senderhwaddr
                    pkt[0].src=interface.ethaddr
                    self.net.send_packet(interface,pkt)
                self.arp_q.remove(it)
                return True

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces=self.net.interfaces()
        self.record=Table()
        self.forward_record=forward_table(self.interfaces)
        self.arpqueue=queue(self.net)
        # other initialization stuff here
    def resend(self):
        now=time.time()
        for it in self.arpqueue.arp_q:
            if it.times>=5:
                for pkt in it.pkt:
                    self.handle_icmp_error("ICMP destination host unreachable",pkt,it.interface)
                self.arpqueue.arp_q.remove(it)
            elif now-it.time>1.0:
                self.net.send_packet(it.port,it.arp)
                it.time=time.time()
                it.times+=1
    def create_icmp_reply(self,ipv4,icmp_request):
        icmp_reply=ICMP()
        icmp_reply.icmptype=ICMPType.EchoReply
        icmp_reply.icmpdata.data=icmp_request.icmpdata.data
        icmp_reply.icmpdata.identifier=icmp_request.icmpdata.identifier
        icmp_reply.icmpdata.sequence=icmp_request.icmpdata.sequence
        ip_reply=IPv4()
        ip_reply.protocol=IPProtocol.ICMP
        ip_reply.ttl=64
        ip_reply.src=ipv4.dst
        ip_reply.dst=ipv4.src
        eth_reply=Ethernet()
        eth_reply.ethertype=EtherType.IP
        reply_icmp=eth_reply+ip_reply+icmp_reply
        return reply_icmp
    def send_pkt(self,pkt,interface):
        log_info("send normal packet")
        dst=pkt.get_header(IPv4).dst
        forward_item=self.forward_record.find_match(dst)
        log_info(forward_item)
        if forward_item.next_ip is None:
            nextip=dst
        else:
            nextip=forward_item.next_ip
        port=self.net.interface_by_name(forward_item.portname)
        nextmac=self.record.get_item(nextip)
        if nextmac is not None:
            pkt[0].dst=nextmac
            pkt[0].src=port.ethaddr
            self.net.send_packet(port,pkt)
        else:
            arp_request = create_ip_arp_request(port.ethaddr,port.ipaddr,nextip)
            self.arpqueue.add_item(arp_request,pkt,port,interface)
    def send_error_pkt(self,error_pkt,interface):
        log_info("send error reply")
        ip_dst=error_pkt.get_header(IPv4).dst
        forward_item=self.forward_record.find_match(ip_dst)
        if forward_item is None:
            pass
        else:
            if forward_item.next_ip is None:
                nextip=ip_dst
            else:
                nextip=forward_item.next_ip
            port=self.net.interface_by_name(forward_item.portname)
            nextmac=self.record.get_item(nextip)
            i=error_pkt.get_header_index(IPv4)
            error_pkt[i].src=port.ipaddr
            if nextmac is not None:
                error_pkt[0].dst=nextmac
                error_pkt[0].src=port.ethaddr
                self.net.send_packet(port,error_pkt)
            else:
                arp_request = create_ip_arp_request(port.ethaddr,port.ipaddr,nextip)
                self.arpqueue.add_item(arp_request,error_pkt,port,interface)
    def create_icmp_error(self,error_msg,origin_packet,interface):
        icmp_error=ICMP()
        if error_msg=="ICMP destination network unreachable":
            icmp_error.icmptype=ICMPType.DestinationUnreachable
            icmp_error.icmpcode=0
        elif error_msg=="ICMP time exceeded":
            icmp_error.icmptype=ICMPType.TimeExceeded
        elif error_msg=="ICMP destination host unreachable":
            icmp_error.icmptype=ICMPType.DestinationUnreachable
            icmp_error.icmpcode=1
        elif error_msg=="ICMP destination port unreachable":
            icmp_error.icmptype=ICMPType.DestinationUnreachable
            icmp_error.icmpcode=3
        i=origin_packet.get_header_index(Ethernet)
        del origin_packet[i]
        icmp_error.icmpdata.data=origin_packet.to_bytes()[:28]
        icmp_error.icmpdata.origdgramlen = len(origin_packet)
        ip_error=IPv4()
        ip_error.protocol=IPProtocol.ICMP
        ip_error.ttl=32
        ipv4=origin_packet.get_header(IPv4)
        ip_error.dst=ipv4.src
        eth_error=Ethernet()
        eth_error.ethertype=EtherType.IP
        pkt_error=eth_error+ip_error+icmp_error
        return pkt_error
    def handle_icmp_error(self,error_msg,origin_packet,interface):
        log_info("Handle error")
        icmp=origin_packet.get_header(ICMP)
        if icmp is not None and (icmp.icmptype==3 or icmp.icmptype==11 or icmp.icmptype==12):
            log_info(icmp.icmptype)
            return
        log_info(origin_packet.get_header(IPv4).src)
        pkt_error=self.create_icmp_error(error_msg,origin_packet,interface)
        log_info(pkt_error.get_header(IPv4).dst)
        self.send_error_pkt(pkt_error,interface)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        try:
            interface=self.net.interface_by_name(ifaceName)
        except KeyError:
            interface=None
        if interface==None or (packet[0].dst!=interface.ethaddr and packet[0].dst!='ff:ff:ff:ff:ff:ff'):
            return 
        log_info(packet.headers())
        log_info(interface.name)
        log_info(interface.ipaddr)
        log_info(interface.ethaddr)
        arp=packet.get_header(Arp)
        ipv4=packet.get_header(IPv4)
        if arp is not None:
            log_info("have arp arp protal is {}".format(arp.targetprotoaddr))
            try:
                port=self.net.interface_by_ipaddr(arp.targetprotoaddr)
            except KeyError:
                port=None
            log_info(port)
            if port!=None:
                if arp.operation==1:
                    self.record.add_item(arp.senderprotoaddr,arp.senderhwaddr)
                    forward_item=self.forward_record.find_match(arp.senderprotoaddr)
                    if forward_item is not None:
                        replypkt=create_ip_arp_reply(port.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                        self.net.send_packet(interface,replypkt)
                    else:
                        pass
                else:
                    if arp.senderhwaddr!='ff:ff:ff:ff:ff:ff':
                        self.record.add_item(arp.senderprotoaddr,arp.senderhwaddr)
                        self.arpqueue.getreply(arp,interface)
            else:
                pass
        if ipv4 is not None:
            log_info("Length {}".format(ipv4.total_length))
            forward_item=self.forward_record.find_match(ipv4.dst)
            if forward_item is None:
                log_info("Network Unreachable")
                self.handle_icmp_error("ICMP destination network unreachable",packet,interface)
            else:
                i=packet.get_header_index(IPv4)
                log_info("i={}".format(i))
                log_info(packet[i])
                log_info(packet[i].ttl)
                flagicmp=False
                for face in self.interfaces:
                    if ipv4.dst==face.ipaddr:
                        icmp_request=packet.get_header(ICMP)
                        if icmp_request is not None and icmp_request.icmptype==ICMPType.EchoRequest:
                            flagicmp=True
                        else:
                            log_info("port unreachable")
                            self.handle_icmp_error("ICMP destination port unreachable",packet,interface)
                            return
                if flagicmp:#icmprequest for me
                    reply_icmp=self.create_icmp_reply(ipv4,icmp_request)
                    self.send_pkt(reply_icmp,interface)
                else:
                    if packet[i].ttl<=1:
                        log_info("TTl -")
                        self.handle_icmp_error("ICMP time exceeded",packet,interface)
                    else:
                        packet[i].ttl-=1
                        self.send_pkt(packet,interface)
   
      
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.resend()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
