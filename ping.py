#! /usr/bin/env python3 
# Team : RemaxBoxTeam
# Author : lhashashinl <--M-->

from typing import Optional, Type, Union
from scapy.packet import Raw
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP 
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP 
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS
from scapy.layers.dns import DNSQR
from scapy.layers.dns import DNSRRDNSKEY
from scapy.layers.dns import DNSRR
import socket,socketserver,unicodedata
import os,sys,subprocess,json,argparse
from prettytable import PrettyTable
import struct,pcapy,hstspreload
from scapy.all import getmacbyip
from scapy.all import get_if_hwaddr
from scapy.all import conf
from scapy.sendrecv import sr1
from scapy.sendrecv import send
import re,scapy,impacket,time


# ============================================
# class main


class ping(object):
    def __new__(cls, *args: Optional[int or str or bool], **kwargs: Union[dict or list]) -> Optional[None]:
        return super(ping, cls).__new__(cls)
    
    def __init__(self, *HOST: Optional[str or list]) -> None:
        if int(len(list(HOST))) > 1: self.HOST = HOST
        else: self.HOST = list(HOST)
        self.SocketIcmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.SocketARP = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.SocketTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.re_hmsm = re.compile("([0-2]?[0-9])[Hh:](([0-5]?[0-9])([Mm:]([0-5]?[0-9])([sS:.]([0-9]{0,3}))?)?)?$")
        self.table = PrettyTable() # Table ping script 
        self.table.field_names = ["count","target","ttl","len","seq","id-icmp"]

    def icmp_socket(self):
        self.SocketIcmp.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.tink = []
        for self.neq in self.tink:
            self.rec, self.addr = self.SocketIcmp.recvfrom(1024)
            self.Header = self.rec[20:28]
            self.TYPE_ICMP, self.ICMP_CODE, self.ICMP_CHECKSUM, self.ID_ICMP, self.SEQUENCE_ICMP = struct.unpack('bbHHh', self.Header)
            return {
                "type":str(self.TYPE_ICMP),
                "code":str(self.ICMP_CODE),
                "checksum":str(self.ICMP_CHECKSUM),
                "id":str(self.ID_ICMP),
                "sequence":str(self.SEQUENCE_ICMP)
            }
    
    def EthernetPacket(self, *args: Union[tuple], **kwargs: Optional[dict]) -> Optional[bytes]:
        if True in args and kwargs:
            packet = (b"\xff"*6)+b"\xfc\xf8\xae"
            packet += b"\x0f\xb1\xd0\x90\x00"
            return packet
        else:
            return Ether(dst=get_if_hwaddr(conf.iface),type="IPv4")
    
    def IPacket(self, IPp: Union[str], *args: Union[tuple], **kwargs: Optional[dict]) -> Optional[bytes]:
        if True in args and kwargs:
            packet = (b"\x00"*2)+b"\x14\x00\x01"
            packet += b"x00\x00@\x00|\xe7\x7f"+(b"\x00"*2)
            packet += b"\x01\x7f\x00\x00\x01"
            return packet
        else:
            return IP(version=4, ihl=5, tos=0x0, id=0, frag=0, flags="DF", 
                      ttl=64, proto='icmp', src=conf.route.route("0.0.0.0")[1],dst=self.HOST)
    
    def IcmpPacket(self, seq_message, *args: Union[tuple], **kwargs: Optional[dict]) -> Optional[bytes]:
        if True in args and kwargs:
            return self.icmp_socket()
        else:
            self.seq_msq = seq_message
            return ICMP(type=8, code=0, id=0x1f66, seq=seq_message ) # echo request
    
    def RawPacket(self):
        self.packet = b"\xeei\x83a"+(b"\x00"*4)
        if b"\x00" and b"\xe12" in self.packet:
            self.packet += b"\xb7d\x0e"+(b"\x00"*5)
            self.listpackther = []
            for self.num in range(int(10),19+1):
                if self.num <= 9:
                    self.num+=1
                    if self.num > 9:
                        self.think = fr"x{self.num}"
                        self.packet += bytes(self.think,'utf-8')
                        if str(self.num) == "19":
                            break
                else: # packet bytes
                    self.think = fr"\x{self.num}"
                    self.packet += bytes(self.think,'utf-8')
                    if str(self.num) == "19":
                        break
        else: # Mikael Alamoot 
            self.packet += b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
        
        try: 
            self.packet += b"\x1a\x1b\x1c\x1d\x1e\x1f"
        except:
            return struct.error 
        
        self.packet += b""" !"#$%&\'()*+,-./"""
          
        try:
            self.packet += bytes("01234567",'utf-8')
            if "0" not in str(self.packet):
                if "8" in str(self.packet):
                    return struct.error
        except:
            for i in range(int(0),int(7)):
                self.packet += bytes(str(i),'utf-8')
            
        return self.packet
    
    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        else:
            sec, milli = divmod(val, 1000)
            min, sec = divmod(sec, 60)
            hour, min = divmod(min, 60)
            return "%d:%d:%d.%d" % (hour, min, sec, int(milli))

    def any2i(self, pkt, val):
        if isinstance(val, str):
            hmsms = self.re_hmsm.match(val)
            if hmsms:
                h, _, m, _, s, _, ms = hmsms.groups()
                ms = int(((ms or "") + "000")[:3])
                val = ((int(h) * 60 + int(m or 0)) * 60 + int(s or 0)) * 1000 + ms  
            else:
                val = 0
        elif val is None:
            val = int((time.time() % (24 * 60 * 60)) * 1000)
        return val
    
    def payload(self, seq_num: Union[int]):
        pack = self.EthernetPacket()/self.IPacket(IPp=self.HOST)/self.IcmpPacket(seq_message=seq_num)/self.RawPacket()
        if len(pack) > 100000:
            return pack 
        else:
            return self.IPacket(IPp=self.HOST)/self.IcmpPacket(seq_message=seq_num)
    
    def send(self, count: Optional[int]=6) -> Optional[list]:
        self.count,self.reslist = int(count),[]
        for self.numseq in range(int(1),int(self.count)+1):
            self.result = sr1(self.payload(self.numseq),verbose=0,iface=conf.route.route("0.0.0.0")[0],timeout=5)
            if self.result == None:
                self.reslist.append("None")
            else:
                self.Target = {
                    "IP":self.result.getlayer(IP).dst,
                    "ttl":self.result.getlayer(IP).ttl,
                    "len":self.result.getlayer(IP).len,
                    "id-icmp":self.result.getlayer(ICMP).id,
                    "seq":self.result.getlayer(IP).seq,
                    "IP-ME":self.result.getlayer(IP).src
                    }
                self.reslist.append(self.Target)
        return self.reslist
    
    def loop(self):
        return send(self.IPacket(self.HOST)/self.IcmpPacket(2)/self.RawPacket(),loop=1,iface=conf.route.route("0.0.0.0")[0])
    
    def __call__(self, *args: Optional[str] or Union[int]) -> Optional[list or dict] or Union[str or int or bool]:
        self.argson = list(args)
        try:
            if int(len(self.send())) > 1000000:
                with open("packet.txt","w") as self.file:
                    self.file.write(str(self.send))
                    self.file.close()
                    return "Saved This File !"
            else:
                return self.table
        except:
            return self.table
    
    def argv(self):
        self.parser = argparse.ArgumentParser(description="...")
        self.parser.add_argument(
            "-t","--target",
            help="ping host target",
            dest="target",
        )
        
        self.parser.add_argument(
            "-c","--count",
            help="count packet number defult 6 packet",
            dest="count",
            default=6
        )
                
        self.parser.add_argument(
            "-l","--loop-send",
            help="loop send payload",
            dest="loop",
            default="false"
        )
        
        self.args = self.parser.parse_args()
        self.TARGET_ARGV = self.args.target
        return {"target":self.args.target,"count":self.args.count,"loop":self.args.loop}
        
        
            

if __name__ == "__main__":
    arg = ping("None").argv()
    if arg:
        if str(arg["loop"]) == "true":
            pi = ping(arg["target"]).loop()
        else: # else if
            pin = ping(arg["target"]).send(count=arg["count"])
            for i in pin:
                #print(i["IP"])
                print(f"ping from\033[31m "+str(i['IP'])+" \033[0m| ttl="+str(i["ttl"])+" len="+str(i["len"])+" id="+str(i["id-icmp"])+" \033[31m"+str(i["seq"])+"\033[0m")
    else:
        os.system("python3 ping.py -h")
        
        
# lhashashinl

