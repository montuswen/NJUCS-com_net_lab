#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *
import threading

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
    def printf(self):
        for key,item in self.tab.items():
            log_info("IP:{} MAC:{}".format(key,item.macaddr))
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
    def printf(self):
        log_info("ip:{} mask:{} nextdes:{} port:{}".format(self.ip,self.mask,self.next_des,self.iface))
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
    def printf(self):
        for it in self.table:
            it.printf()
class queue_item:
    def __init__(self,arp,port):
        self.arp=arp
        self.pkt=[]
        self.time=time.time()
        self.times=1
        self.port=port
    def add_packet(self,pkt):
        self.pkt.append(pkt)
    def matches(self,senderaddr):
        return self.arp.get_header(Arp).targetprotoaddr==senderaddr

class queue:
    def __init__(self,net):
        self.arp_q=[]
        self.net=net
    def add_item(self,arp,pkt,port):
        for item in self.arp_q:
            if item.arp.get_header(Arp).targetprotoaddr==arp.get_header(Arp).targetprotoaddr:
                item.add_packet(pkt)
                return True
        log_info("!!!")
        newitem=queue_item(arp,port)
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
    def resend(self):
        now=time.time()
        for it in self.arp_q:
            if it.times>=5:
                self.arp_q.remove(it)
            elif now-it.time>1.0:
                log_info("Fa Le")
                log_info(it.arp.get_header(Arp).targetprotoaddr)
                self.net.send_packet(it.port,it.arp)
                it.time=time.time()
                it.times+=1

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces=self.net.interfaces()
        self.record=Table()
        self.forward_record=forward_table(self.interfaces)
        self.arpqueue=queue(self.net)
        # other initialization stuff here

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
            forward_item=self.forward_record.find_match(ipv4.dst)
            if forward_item is None:
                pass
            else:
                ipv4.ttl-=1
                if ipv4.ttl<=0:
                    pass
                else:
                    if forward_item.next_ip is None:
                        nextip=ipv4.dst
                    else:
                        nextip=forward_item.next_ip
                    # self.record.printf()
                    port=self.net.interface_by_name(forward_item.portname)
                    nextmac=self.record.get_item(nextip)
                    if nextmac is not None:
                        packet[0].dst=nextmac
                        packet[0].src=port.ethaddr
                        self.net.send_packet(port,packet)
                        log_info("???")
                    else:
                        log_info(ipv4.dst)
                        log_info(forward_item.portname)
                        log_info(nextip)
                        flag=True
                        for item in self.interfaces:
                            if item.ipaddr==nextip:
                                flag=False
                        if flag:
                            arp_request = create_ip_arp_request(port.ethaddr,port.ipaddr,nextip)
                            self.arpqueue.add_item(arp_request,packet,port)
                        else:
                            pass
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.arpqueue.resend()
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
