from scapy.compat import bytes_hex
from scapy.utils import rdpcap

Packets = rdpcap("vzorky_pcap_na_analyzu\\\\eth-1.pcap")


mini = bytes_hex(Packets[0])
for x in Packets[0]:
    print(bytes_hex(x))
print(mini)