
import scapy.all as scapy
from scapy.layers import http

def get_interface():
    interfaces = scapy.get_if_list()

    print("\n사용 가능한 인터페이스 목록:")
    interfaces = scapy.get_working_ifaces()
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}: {iface.name}  ({iface.description})")

    while True:
        try:
            choice = int(input("\n인터페이스 번호 선택: "))
            if 1 <= choice <= len(interfaces) :
                return interfaces[choice - 1]
            else:
                print("잘못된 번호입니다. 다시 입력하세요.")
        except ValueError:
            print("숫자만 입력해야 합니다.")

def sniff(interface):
    scapy.sniff(iface=interface.name, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        method = packet[http.HTTPRequest].Method.decode()
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        print(f"[+] {method} http://{host}{path}")

        if packet.haslayer(scapy.Raw):
            print("Raw Data:")
            print(packet[scapy.Raw].load)
            print("------------------------")


sniff(get_interface())