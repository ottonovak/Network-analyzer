from scapy.compat import bytes_hex
from scapy.utils import rdpcap

packets = rdpcap("vzorky_pcap_na_analyzu\\\\eth-1.pcap")

index_frame = 1

for packet in packets:

    # Vypis ramca (Poradové číslo rámca v analyzovanom súbore)
    print("rámec " + str(index_frame))
    index_frame += 1

    # Vypis dlzonk (Dĺžku rámca v bajtoch poskytnutú pcap API a dĺžku tohto rámca prenášaného po médiu)
    dlzka_ramca = len(packet)
    print("dĺžka rámca poskytnutá pcap API -", dlzka_ramca, "B")
    print("dĺžka rámca prenášaného po médiu –", max(64, dlzka_ramca + 4), "B")

    # Vypis typu ramca (– Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 - Raw)
    hex_packet = bytes_hex(packet)
    str1 = hex_packet[24:28]
    str2 = hex_packet[28:30]

    if int(str1, 16) > 1500:
        print("Ethernet II")
    elif str2 == "FF":
        print("IEEE 802.3 - Raw")
    elif str2 == "AA":
        print("IEEE 802.3 s LLC a SNAP")
    else:
        print("IEEE 802.3 LLC\n")

    # Vypis adres (Zdrojovú a cieľovú fyzickú (MAC) adresu uzlov, medzi ktorými je rámec prenášaný)
    print("Zdrojová MAC adresa: ", end="") # Vypis zdrojovej MAC adresy
    for i in range(6):
        if i != 5:
            print(chr(hex_packet[i * 2 + 12]) + chr(hex_packet[i * 2 + 13]), end=" ")
        else:
            print(chr(hex_packet[i * 2 + 12]) + chr(hex_packet[i * 2 + 13]))

    print("Cieľová MAC adresa: ", end="") # Vypis cielovej MAC adresy
    for i in range(6):
        if i != 5:
            print(chr(hex_packet[i * 2]) + chr(hex_packet[i * 2 + 1]), end=" ")
        else:
            print(chr(hex_packet[i * 2]) + chr(hex_packet[i * 2 + 1]))

    # Vypis celeho ramca
    for i in range(dlzka_ramca):
        str1 = hex_packet[i*2]
        str2 = hex_packet[i*2+1]

        if(i % 8 == 0 and i != 0 and i % 16 != 0):  # Pre oddelenie v prostriedku riadku
            print(" " + chr(str1) + chr(str2), end=" ")
        elif(i % 16 == 0 and i != 0):               # Pre novy riadok
            print("\n" + chr(str1) + chr(str2), end=" ")
        else:
            print(chr(str1) + chr(str2), end=" ")   # Pre vsetky ine

    print("\n") # Oddelenie medzi ramcami