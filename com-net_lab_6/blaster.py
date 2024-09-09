#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
import struct
starttime=0# first packet time 
totaltime=0# first to end time = endtime-starttime
retrantimes=0# retransmit times
timeouttimes=0# timeout times
allbytes=0# all packte bytes
allbytesonce=0# packte bytes without retransmit
throughput=0# allbytes / totaltime
goodput=0# allbytesonce / totaltime
class Item:
    def __init__(self,pkt,sequencenumber,time):
        self.pkt=pkt
        self.sequencenumber=sequencenumber
        self.acked=False
class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp=IPv4Address(blasteeIp)
        self.num=int(num)
        if self.num<=0:
            log_info("error parameter 'num'")
            return
        self.length=int(length)
        if not (self.length>=0 and self.length<=65535):
            log_info("error parameter 'length'")
            return
        self.senderWindow=int(senderWindow)
        self.timeout=float(int(timeout)/1000)
        self.recvTimeout=float(int(recvTimeout)/1000)
        self.queue=[]
        self.timestamp=0
        self.retranqueue=[]
        self.left=1
        self.right=0

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        global starttime, totaltime, retrantimes, timeouttimes, allbytes, allbytesonce, throughput, goodput
        _, fromIface, packet = recv
        log_debug("I got a packet")
        rawbytes  = packet[3].to_bytes()
        rawsequencenumber = rawbytes[0:4]
        sequencenumber = struct.unpack('!I', rawsequencenumber)[0]
        log_info('receive the sequencenumber{} ack_packet'.format(sequencenumber))
        if self.left>self.right:
            log_info("the ack_packet is repetited")
            return
        if sequencenumber==self.queue[0].sequencenumber:
            self.queue[0].acked=True
            i=0
            while i<len(self.queue) and self.queue[i].acked:
                i+=1
                self.left+=1
                self.timestamp=time.time()
            if i<len(self.queue):
                self.queue=self.queue[i:]
            else:
                self.queue=[]
        else:
            for item in self.queue:
                if item.sequencenumber==sequencenumber:
                    item.acked=True
                    break
        log_info('now left is{} right is{}'.format(self.left,self.right))
        if self.left==self.num+1:
            totaltime=time.time()-starttime
            throughput=allbytes/totaltime
            goodput=allbytesonce/totaltime
            log_info("totaltime{:.4f} throughput{:.4f} goodput{:.4f}".format(totaltime,throughput,goodput))
            log_info("retrantimes{} timeouttimes{}".format(retrantimes,timeouttimes))
            log_info("allbytes{} allbytesonce{}".format(allbytes,allbytesonce))
            log_info("all down!")
            self.shutdown()
            return
            
    def handle_no_packet(self):
        global starttime, totaltime, retrantimes, timeouttimes, allbytes, allbytesonce, throughput, goodput
        log_debug("Didn't receive anything")
        if self.left==self.num+1:
            log_info("all down!")
            return
        if len(self.retranqueue)!=0:
            log_info('going to retransmit')
            log_info('retransmit the sequencenumber{} packt'.format(self.retranqueue[0].sequencenumber))
            self.net.send_packet('blaster-eth0',self.retranqueue[0].pkt)
            retrantimes+=1
            allbytes+=self.length
            self.retranqueue.remove(self.retranqueue[0])
            return   
        if self.right<self.num and self.right-self.left+1<self.senderWindow:
            # Creating the headers for the packet
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP
            pkt[1].src=IPv4Address("192.168.100.1")
            pkt[1].dst=IPv4Address("192.168.200.1")
            pkt[1].ttl=64
            pkt[0].src=EthAddr("10:00:00:00:00:01")
            pkt[0].dst=EthAddr("40:00:00:00:00:01")
            log_info('right is moving')
            self.right+=1
            sequencenumber=self.right
            rawsequencenumber=sequencenumber.to_bytes(4,byteorder='big')
            rawlength=self.length.to_bytes(2,byteorder='big')
            rawcontent=bytes([0]*self.length)
            pkt+=RawPacketContents(rawsequencenumber)
            pkt+=RawPacketContents(rawlength)
            pkt+=RawPacketContents(rawcontent)
            log_info('first time send_packet with sequencenumber{}'.format(sequencenumber))
            self.net.send_packet('blaster-eth0',pkt)
            if sequencenumber==1:
                starttime=time.time()
            self.queue.append(Item(pkt,sequencenumber,starttime))
            allbytes+=self.length
            allbytesonce+=self.length
            log_info('now left is{} right is{}'.format(self.queue[0].sequencenumber,self.queue[-1].sequencenumber))
        elif time.time()-self.timestamp>=self.timeout:
            log_info("timeout!!!")
            timeouttimes+=1
            for item in self.queue:
                if item.acked==False:
                    self.retranqueue.append(item)
            log_info('timeout and retransmit the sequencenumber{} packt'.format(self.retranqueue[0].sequencenumber))
            self.net.send_packet('blaster-eth0',self.retranqueue[0].pkt)
            retrantimes+=1
            allbytes+=self.length
            self.retranqueue.remove(self.retranqueue[0])
            
    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
