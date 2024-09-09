'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    maclist=[]
    interlist=[]
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.src not in maclist:
            maclist.append(eth.src)
            interlist.append(fromIface)
        if eth.src in maclist:
            ind=maclist.index(eth.src)
            interlist[ind]=fromIface
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in maclist:
                ind=maclist.index(eth.dst)
                intfdst=interlist[ind]
                for intf in my_interfaces:
                    if intf.name == intfdst:
                        log_info(f"Send a packedt to {intfdst}")
                        net.send_packet(intf,packet)
                        break
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
        # log_info(f"Maclist:")
        # for it in maclist:
        #     log_info(f" {it} ")
        # log_info(f"Interfacelist:")
        # for it in interlist:
        #     log_info(f" {it} ")
    net.shutdown()
