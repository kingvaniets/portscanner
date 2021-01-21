#!/usr/bin/env python3
import sys
import os
from time import *
import argparse
from scapy.layers.l2 import Ether
from scapy.sendrecv import *
from scapy.layers.inet import IP, TCP, ICMP
from datetime import datetime
import argparse

# TCP Flags:
xmas_flags = "FPU"
syn_flags = "S"
fin_flags = "F"
null_flags = ""
ack_flags = "A"
rstack = "RA"
force = False
voorbeeld = "Voorbeeld van gebruik: portscanner.py -sS -p 22,443,80,1010 -ip 1.1.1.1"
parser = argparse.ArgumentParser(epilog=voorbeeld)

parser.add_argument("-sS", help="Stealth Scan", action='store_true')
parser.add_argument("-sT", help="Connect Scan", action='store_true')
parser.add_argument("-sX", help="Christmas Scan", action='store_true')
parser.add_argument("-sF", help="Fin Scan", action='store_true')
parser.add_argument("-sN", help="Null Scan", action='store_true')
parser.add_argument("-sA", help="TCP Ack Scan", action='store_true')
parser.add_argument("-sW", help="TCP Window Scan", action='store_true')
parser.add_argument("-p", "--ports", help="enter one or more ports", nargs="*", required=True)
parser.add_argument("-ip", "--ip_address", help="Destination IP", required=True)
parser.add_argument("-f", "--force", help="force scan even though host seems down", default=False, action='store_true')
args = parser.parse_args()


def stealthscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=syn_flags), verbose=0, timeout=1)
    print("PORT\t\tSTATE\t")
    ans, unans = pakketjes
    for ant in ans:
        if ant[1]['TCP'].flags == 'SA':
            send(IP(dst=dstip) / TCP(dport=ports, flags='R'), verbose=0)
            print(ant[1].sport, "/TCP", "\topen\t")
        else:
            print(ant[0].dport, "/TCP", "\tclosed\t")
    if len(unans) > 0:
        print("not show: ", len(unans), " packets because of no reply")


def connectscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=syn_flags), verbose=0, timeout=1)
    print("PORT\t\tSTATE")
    ans, unans = pakketjes
    for ant in ans:
        if ant[1]['TCP'].flags == 'SA':
            send(IP(dst=dstip) / TCP(dport=ports, flags=rstack), verbose=0)
            print(ant[1].sport, "/TCP", "\topen\t")
        else:
            print(ant[0].dport, "/TCP", "\tclosed\t")
    if len(unans) > 0:
        print("not show: ", len(unans), " packets because of no reply")


def xmassscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=xmas_flags), verbose=0, timeout=1)
    if str(pakketjes) == "None":
        print("no packets sent or received")
    else:
        print("PORT\t\tSTATE")
        ans, unans = pakketjes
        for nant in unans:
            print(nant[0].dport, "/TCP", "\topen|filtered\t")
        for ant in ans:
            prot = ant[1].summary().split(" ")[2]
            if prot == "TCP":
                if ant[1]['TCP'].flags == "RA":
                    print(ant[1].sport, "/TCP", "\tclosed\t")
                else:
                    print("unexpeted flags reply: ", ant[1]['TCP'].flags)
            if prot == "ICMP":
                print(ant[1].sport, "/ICMP", "\tfiltered\t")


def finscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=fin_flags), verbose=0, timeout=1)
    if str(pakketjes) == "None":
        print("no packets sent or received")
    else:
        print("PORT\t\tSTATE")
        ans, unans = pakketjes
        for nant in unans:
            print(nant[0].dport, "/TCP", "\topen|filtered\t")
        for ant in ans:
            prot = ant[1].summary().split(" ")[2]
            if prot == "TCP":
                if ant[1]['TCP'].flags == "RA":
                    print(ant[1].sport, "/TCP", "\tclosed\t")
                else:
                    print("unexpeted flags reply: ", ant[1]['TCP'].flags)
            if prot == "ICMP":
                print(ant[1].sport, "/ICMP", "\tfiltered\t")


def nullscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=null_flags), verbose=0, timeout=1)
    if str(pakketjes) == "None":
        print("no packets sent or received")
    else:
        print("PORT\t\tSTATE")
        ans, unans = pakketjes
        for nant in unans:
            print(nant[0].dport, "/TCP", "\topen|filtered\t")
        for ant in ans:
            prot = ant[1].summary().split(" ")[2]
            if prot == "TCP":
                if ant[1]['TCP'].flags == "RA":
                    print(ant[1].sport, "/TCP", "\tclosed\t")
                else:
                    print("unexpeted flags reply: ", ant[1]['TCP'].flags)
            if prot == "ICMP":
                print(ant[1].sport, "/ICMP", "\tfiltered\t")


def tcpackscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=ack_flags), verbose=0, timeout=1)
    #icmpans=sniff(filter="icmp", timeout =5,count=5) #code zou moeten kloppen maar ik krijg nooit ICMP foutbericht terug. zelfs niet met sniffer.
    #print(icmpans)
    if str(pakketjes) == "None":
        print("no packets sent or received")
    else:
        print("PORT\t\tSTATE")
        ans, unans = pakketjes
        for ant in ans:
            prot = ant[1].summary().split(" ")[2]
            if prot == "TCP":
                if ant[1]['TCP'].flags == "R":
                    print(ant[1].sport, "/TCP", "\tunfiltered\t")
                else:
                    print("unexpeted flags reply: ", ant[1]['TCP'].flags)
            if prot == "ICMP":
                print(ant[1].sport, "/ICMP", "\tfiltered\t")
        if len(unans) > 0:
            print("not show: ", len(unans), " packets because of no reply")


def tcpwindowscan(ports, dstip):
    pakketjes = sr(IP(dst=dstip) / TCP(dport=ports, flags=ack_flags), verbose=0, timeout=1)
    if str(pakketjes) == "None":
        print("no packets sent or received")
    else:
        print("PORT\t\tSTATE")
        ans, unans = pakketjes
        for ant in ans:
            prot = ant[1].summary().split(" ")[2]
            if prot == "TCP":
                if ant[1]['TCP'].flags == "R":
                    windowsize = ant[1]['TCP'].window
                    if (windowsize == 0):
                        print(ant[1].sport, "/TCP", "\tclosed\t")
                    if (windowsize > 0):
                        print(ant[1].sport, "/TCP", "\topen\t")
                else:
                    print("unexpeted flags reply: ", ant[1]['TCP'].flags)
            if prot == "ICMP":
                print(ant[1].sport, "/ICMP", "\tfiltered\t")
        print("not show: ", len(unans), " packets because of no reply")


def latency_ping(host, count=3):  # latency test met ping
    packet = Ether() / IP(dst=host) / ICMP()
    conf.dstmac = packet.sprintf("%Ether.dst%")  # heeft ook MAC adres
    t = 0.0
    for x in range(count):
        ans, unans = srp(packet, filter='icmp', verbose=0)
        rx = ans[0][1]
        tx = ans[0][0]
        delta = rx.time - tx.sent_time
        t += delta
    return (t / count)


def host_up(dstip):
    ans, unans = srp(Ether() / IP(dst=dstip) / ICMP(), filter='icmp', verbose=0, timeout=1)
    if len(ans) == 0:
        if force:
            print("Host seems to be down but we're forcing it.")
            return True
        print("Hosts seems to be unreachable or down. If you want to try anyways, set the paramater force to True")
        return False
    elif len(ans) == 1:
        print("Host seems to be UP")
        return True


dports = list(map(int, args.ports[0].split(",")))
dst_ip = args.ip_address
print("\nStarting scan at " + datetime.utcnow().strftime("%Y-%m-%d %H:%M"))
if host_up(dst_ip):
    print("Host has " + str(latency_ping(dst_ip)) + "s latency).")
    if args.sS:
        print("Chosen Stealth Scan")
        stealthscan(dports, dst_ip)
    if args.sT:
        print("Chosen Connect Scan")
        connectscan(dports, dst_ip)
    if args.sX:
        print("Chosen Christmas Scan")
        xmassscan(dports, dst_ip)
    if args.sF:
        print("Chosen Fin Scan")
        finscan(dports, dst_ip)
    if args.sN:
        print("Chosen Null Scan")
        nullscan(dports, dst_ip)
    if args.sA:
        print("Chosen TCP Ack Scan")
        tcpackscan(dports, dst_ip)
    if args.sW:
        print("Chosen Window Scan")
        tcpwindowscan(dports, dst_ip)
