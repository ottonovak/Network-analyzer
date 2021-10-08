from scapy.compat import bytes_hex
from scapy.utils import rdpcap

packets = rdpcap("vzorky_pcap_na_analyzu\\\\eth-1.pcap")

mini = bytes_hex(packets[1])
index_frame = 1

#for packet in packets:
packet =packets[0]
print("rámec " + str(index_frame))
index_frame += 1
dlzka_ramca = len(packet)
print("dĺžka rámca poskytnutá pcap API - " + str(dlzka_ramca) + " B")
print("dĺžka rámca prenášaného po médiu –  - " + str(max(64, dlzka_ramca + 4)) + " B")

hex_packet = bytes_hex(packet)
str1 = hex_packet[24:28]
str2 = hex_packet[28:30]
print(str1)
if(int(str1,16) > 1500):
    print("Ethernet II")
elif(str2 == "FF"):
    print("IEEE 802.3 Raw")
elif(str2 == "AA"):
    print("IEEE 802.3 LLC SNAP")
else:
    print("IEEE 802.3 LLC\n")

for i in range(dlzka_ramca):
    str1 = hex_packet[i*2]
    str2 = hex_packet[i*2+1]
    if(i % 8 == 0 and i != 0 and i % 16 != 0): #pre oddelenie v prostriedku riadku
        print("  " + chr(str1) + chr(str2), end=" ")
    elif(i % 16 == 0 and i != 0): #pre novy riadok
        print("\n" + chr(str1) + chr(str2), end=" ")
    else:
        print(chr(str1) + chr(str2), end=" ") # vstky ine


print("\n")
