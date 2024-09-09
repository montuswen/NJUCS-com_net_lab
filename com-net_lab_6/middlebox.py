#!/usr/bin/env python3

import time
import threading
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
import random

class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        rawbytes=packet[3].to_bytes()
        rawsequencenumber=rawbytes[0:4]
        sequencenumber = struct.unpack('!I', rawsequencenumber)[0]
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            p=random.uniform(0,1)
            if(p<=self.dropRate):
                log_info('Drop the sequencenumber{} packet'.format(sequencenumber))
                return
            port=self.net.interface_by_name("middlebox-eth1")
            packet[0].src=port.ethaddr
            packet[0].dst=EthAddr('20:00:00:00:00:01') 
            log_info('transmit the sequencenumber{} packet to blastee'.format(sequencenumber))
            self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            port=self.net.interface_by_name("middlebox-eth0")
            packet[0].src=port.ethaddr
            packet[0].dst=EthAddr('10:00:00:00:00:01')
            log_info('transmit the sequencenumber{} ack_packet to blaster'.format(sequencenumber))
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
