# Napisal Stefan Otto Novak

from os import walk
from scapy.compat import bytes_hex
from scapy.utils import rdpcap
import hashlib

FILE = open(r"vypis.txt","w")

                # 1. Bod Zadania
files = []      # Program cita vsetky subory z priecinku "subory_na_analyzu"

for (dirpath, dirnames, filenames) in walk("./subory_na_analyzu"):
    files.extend(filenames)

for filename in files:

    FILE.write("\n<<<<<<<< Analyzujes subor " + filename + " >>>>>>>>\n")
    packets = rdpcap(f"./subory_na_analyzu/{filename}")

    index_frame = 1

    for packet in packets:
        # Vypis ramca (Poradové číslo rámca v analyzovanom súbore)
        FILE.write("rámec " + str(index_frame) + "\n")
        index_frame += 1

        # Vypis dlzonk (Dĺžku rámca v bajtoch poskytnutú pcap API a dĺžku tohto rámca prenášaného po médiu)
        dlzka_ramca = len(packet)
        FILE.write("dlzka ramca poskytnuta pcap API - " + str(dlzka_ramca) + "B\n")
        FILE.write("dlzka ramca prenasaneho po mediu – " + str(max(64, dlzka_ramca + 4)) + "B\n")

        # Vypis typu ramca (– Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 - Raw)
        hex_packet = bytes_hex(packet)
        str1 = hex_packet[24:28]
        str2 = hex_packet[28:30]

        if int(str1, 16) > 1500:
            FILE.write("Ethernet II\n")
            vnoreny_protokol = "Ethertype " + str(str1.decode())

        elif str2.decode() == "ff" or str2.decode() == "FF":
            FILE.write("IEEE 802.3 - Raw\n")
            vnoreny_protokol = "IPX"

        elif str2.decode() == "aa" or str2.decode() == "AA":
            FILE.write("IEEE 802.3 s LLC a SNAP\n")

        else:
            FILE.write("IEEE 802.3 LLC\n")

        # Vypis adres (Zdrojovú a cieľovú fyzickú (MAC) adresu uzlov, medzi ktorými je rámec prenášaný)
        # Vypis zdrojovej MAC adresy
        FILE.write("Zdrojova MAC adresa: ")
        for i in range(6):
            if i != 5:
                FILE.write(chr(hex_packet[i * 2 + 12]) + chr(hex_packet[i * 2 + 13]) + " ")
            else:
                FILE.write(chr(hex_packet[i * 2 + 12]) + chr(hex_packet[i * 2 + 13]) + "\n")

        # Vypis cielovej MAC adresy
        FILE.write("Cielova MAC adresa: ")
        for i in range(6):
            if i != 5:
                FILE.write(chr(hex_packet[i * 2]) + chr(hex_packet[i * 2 + 1]) + " ")
            else:
                FILE.write(chr(hex_packet[i * 2]) + chr(hex_packet[i * 2 + 1]) + "\n")

        # Vypis vnoreneho protokola
        FILE.write(vnoreny_protokol + "\n")

        # Vypis celeho ramca
        for i in range(dlzka_ramca):    # Iterujem cez kazdy dajt
            str1 = hex_packet[i * 2]
            str2 = hex_packet[i * 2 + 1]

            if i % 16 == 15:                                # Pre posledny riadok
                FILE.write(chr(str1) + chr(str2) + "\n")
            elif i % 8 == 0 and i != 0 and i % 16 != 0:     # Pre oddelenie v prostriedku riadku
                FILE.write(" " + chr(str1) + chr(str2) + " ")
            elif i == dlzka_ramca - 1:                      # Pre osetrenie medzery za poslednym bajtom
                FILE.write(chr(str1) + chr(str2) + "\n\n")
            else:                                           # Pre vsetky ine
                FILE.write(chr(str1) + chr(str2) + " ")

# 2. Bod Zadania

FILE.close()