#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

time_out=120
class Table_item:
    def __init__(self,macaddr):
        self.time=time.time()
        self.macaddr=macaddr
    def Timeout(self):
        return (time.time()-self.time)>time_out
class Table:
    def __init__(self):
        self.tab={}
    def get_tab(self):
        return self.tab
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
        # self.get_item(key)
        # for k,item in self.tab.items():
        #     log_info("??IP:{} MAC:{} TIME:{}??".format(k,item.macaddr,item.time))
        self.tab[key]=Table_item(mac)

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.record=Table()
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp=packet.get_header(Arp)
        if arp is not None:
            try:
                interface=self.net.interface_by_ipaddr(arp.targetprotoaddr)
            except KeyError:
                interface=None
            if interface is not None:
                if arp.operation==1:
                    replypkt=create_ip_arp_reply(interface.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,replypkt)
                else:
                    pass
            else:
                pass
            self.record.add_item(arp.senderprotoaddr,arp.senderhwaddr)
            for k,item in self.record.get_tab().items():
                log_info("IP:{} MAC:{} TIME:{}".format(k,item.macaddr,item.time))



    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
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
