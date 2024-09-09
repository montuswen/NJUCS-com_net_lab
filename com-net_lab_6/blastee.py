#!/usr/bin/env python3

import time
import threading
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
import struct

class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp=IPv4Address(blasterIp)
        self.num=int(num)
        self.dic={}
        for i in range(1,self.num+1):
            self.dic[str(i)]=False

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        rawbytes=packet[3].to_bytes()
        rawsequencenumber=rawbytes[0:4]
        sequencenumber = struct.unpack('!I', rawsequencenumber)[0]
        contents=rawbytes[6:]
        contents=contents[:8]
        ack=Ethernet() + IPv4(protocol = IPProtocol.UDP) + UDP()
        ack[0].src=EthAddr("20:00:00:00:00:01")
        ack[0].dst=EthAddr("40:00:00:00:00:02")
        ack[1].ttl=64
        ack[1].src=IPv4Address("192.168.200.1")
        ack[1].dst=self.blasterIp
        ack+=RawPacketContents(rawsequencenumber)
        ack+=RawPacketContents(contents)
        log_info('receive and reply the sequencenumber{} packet'.format(sequencenumber))
        self.net.send_packet("blastee-eth0", ack)
        flag=False
        self.dic[str(sequencenumber)]=True
        for i in range(1,self.num+1):
            if self.dic[str(i)]==False:
                flag=True
        if not flag:
            self.shutdown()

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
