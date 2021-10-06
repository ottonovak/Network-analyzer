from scapy.compat import bytes_hex
from scapy.utils import rdpcap

packets = rdpcap("vzorky_pcap_na_analyzu\\\\eth-1.pcap")

mini = bytes_hex(packets[1])
index_frame = 1

for packet in packets:
    print("rámec " + str(index_frame))
    index_frame += 1
    print("dĺžka rámca poskytnutá pcap API - " + str(len(packet)) + " B")
    print("dĺžka rámca prenášaného po médiu –  - " + str(max(64, len(packet) + 4)) + " B")

    hex_packet = bytes_hex(packet)
    str1 = hex_packet[24:28]
    str2 = hex_packet[28:30]

    if(int(str1,16) > 1500):
        print("Ethernet II")
    elif(str2 == "FF"):
        print("IEEE 802.3 Raw")
    elif(str2 == "AA"):
        print("IEEE 802.3 LLC SNAP")
    else:
        print("IEEE 802.3 LLC\n")
    print(hex_packet)
    print("\n")
