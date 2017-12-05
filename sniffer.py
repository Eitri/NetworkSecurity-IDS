#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets
#Adapted from
#http://www.binarytides.com/python-packet-sniffer-code-linux/
#Silver Moon (m00n.silv3r@gmail.com)

import socket, sys, time
from struct import *

class Sniffer:
#Convert a string of 6 characters of ethernet address into a dash separated hex string
    def eth_addr (self, a) :
      b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
      return b

    def run(self):
        time_end = time.time() + 10
        while time.time() < time_end:
            packet = self.s.recvfrom(65565)
            #packet string from tuple
            packet = packet[0]

            #parse ethernet header
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = unpack('!6s6sH' , eth_header)
            eth_protocol = socket.ntohs(eth[2])

            #Parse IP packets, IP Protocol number = 8
            if eth_protocol == 8 :
                #Parse IP header
                #take first 20 characters for the ip header
                ip_header = packet[eth_length:20+eth_length]

                #now unpack them :)
                iph = unpack('!BBHHHBBH4s4s' , ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4

                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8]);
                d_addr = socket.inet_ntoa(iph[9]);

                #print 'Source Address : ' + str(s_addr) + '\nDestination Address : ' + str(d_addr)

                #TCP protocol
                if protocol == 6 :
                    t = iph_length + eth_length
                    tcp_header = packet[t:t+20]
                    tcph = unpack('!HHLLBBHHH' , tcp_header)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    #print 'Source Port : ' + str(source_port) + '\nDest Port : ' + str(dest_port) + '\nProtocol : TCP'

                #UDP packets
                elif protocol == 17 :
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u+8]

                    #now unpack them :)
                    udph = unpack('!HHHH' , udp_header)

                    source_port = udph[0]
                    dest_port = udph[1]
                    #print 'Source Port : ' + str(source_port) + '\nDest Port : ' + str(dest_port) + '\nProtocol : UDP'
                #some other IP packet like IGMP
                #else :
                    #print 'Protocol other than TCP/UDP'

                flow = self.buffer.get((str(s_addr), str(d_addr), str(source_port), str(dest_port), protocol))
                now = time.time()
                if ( flow == None):
                    #print "New"
                    self.buffer[(str(s_addr), str(d_addr), str(source_port), str(dest_port), protocol)] = [now, now, 0]
                else:
                    #print "Update"
                    self.buffer[(str(s_addr), str(d_addr), str(source_port), str(dest_port), protocol)] = [flow[0], now, now-flow[0]]
        return self.buffer
    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    def __init__(self):
        try:
            self.buffer = {}
            self.s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
