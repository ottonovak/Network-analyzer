# Napisal Stefan Otto Novak

from os import walk
from scapy.compat import bytes_hex
from scapy.utils import rdpcap
import hashlib

files = []
ETHER_types = {}
LSAP_types = {}
IPprotocols = {}
TCPports = {}
UDPports = {}
source_IP_adresses = {}
source_IPv4_adresses = {}
FILE_VYPIS = open(r"vypis.txt", "w")

def protocol_initialization():
    global ETHER_types, LSAP_types, IPprotocols, TCPports, UDPports # Prikaz "global" aby zapisoval do glabalnych premennich
    FILE_PROTOKOLY = open('protokoly.txt', 'r')

    type_of_protocol = ""
    for line in FILE_PROTOKOLY:
        if line[0] == "#":
            type_of_protocol = line[1:len(line) - 1]
            continue

        if line[0] != "0":  # Vynimka, kazdy protokol zacina z hex cislo "0x-----"
            continue

        line = line.strip()         # "strip" vymaze nove riadky so stringu
        words = line.split(" ")     # Vytvori pole slov
        str1_int = int(words[1])
        nested_protocol = words[2]

        if len(words) >= 4:     # Vynimka pre nazvy vnorenych protokolova z viac slov
            for word in words[3:]:
                nested_protocol += " " + word

        if type_of_protocol == "ETHER":
            ETHER_types[str1_int] = nested_protocol

        elif type_of_protocol == "LSAP":
            LSAP_types[str1_int] = nested_protocol

        elif type_of_protocol == "IP":
            IPprotocols[str1_int] = nested_protocol

        elif type_of_protocol == "TCP":
            TCPports[str1_int] = nested_protocol

        elif type_of_protocol == "UDP":
            UDPports[str1_int] = nested_protocol

    FILE_PROTOKOLY.close()

def add_ip_to_list(hex_packet ,type):
    global source_IPv4_adresses,source_IPv4_adresses
    adr1 = int(hex_packet[52:54], 16)
    adr2 = int(hex_packet[54:56], 16)
    adr3 = int(hex_packet[56:58], 16)
    adr4 = int(hex_packet[58:60], 16)
    adress_str = str(adr1) + "." + str(adr2) + "." + str(adr3) + "." + str(adr4)  # Vytori string adrese

    if type == "IP":
        if source_IP_adresses.__contains__(adress_str):   # Ak adresa sa nachadza v slovniku, pripocita pocet vyskitnutii
            source_IP_adresses[adress_str] += 1
        else:
            source_IP_adresses[adress_str] = 1            # Ked adresa sa 1x vyskitla
    elif type == "IPv4":
        if source_IPv4_adresses.__contains__(adress_str):
            source_IPv4_adresses[adress_str] += 1
        else:
            source_IPv4_adresses[adress_str] = 1

def find_ether_type(hex_packet):
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
    str1 = hex_packet[24:28]
    index_dictionary = int(str1.decode(), 16)

    if ETHER_types.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        add_ip_to_list(hex_packet, "IP")
        if ETHER_types[index_dictionary] == "IPv4":
            add_ip_to_list(hex_packet, "IPv4")
        return ETHER_types[index_dictionary]
    else:
        return "Tento Ethertype nie je uvedeny v databaze"

def find_lsap_type(hex_packet):
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
    str2 = hex_packet[28:30]
    index_dictionary = int(str2.decode(), 16)

    if LSAP_types.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        return LSAP_types[index_dictionary]
    else:
        return "Tento LSAP nie je uvedeny v databaze"

protocol_initialization()

for (dirpath, dirnames, filenames) in walk("./subory_na_analyzu"):
    # Program cita vsetky subory z priecinku "subory_na_analyzu"
    files.extend(filenames)

for filename in files:

    FILE_VYPIS.write("\n<<<<<<<< Analyzujes subor " + filename + " >>>>>>>>\n")
    packets = rdpcap(f"./subory_na_analyzu/{filename}")

    index_frame = 1

    for packet in packets:
        # Vypis ramca (Poradové číslo rámca v analyzovanom súbore)
        FILE_VYPIS.write("rámec " + str(index_frame) + "\n")
        index_frame += 1
        vnoreny_protokol = ""

        # Vypis dlzonk (Dĺžku rámca v bajtoch poskytnutú pcap API a dĺžku tohto rámca prenášaného po médiu)
        dlzka_ramca = len(packet)
        FILE_VYPIS.write("dlzka ramca poskytnuta pcap API - " + str(dlzka_ramca) + "B\n")
        FILE_VYPIS.write("dlzka ramca prenasaneho po mediu – " + str(max(64, dlzka_ramca + 4)) + "B\n")

        # Vypis typu ramca (– Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 - Raw)
        hex_packet = bytes_hex(packet)
        str1 = hex_packet[24:28]
        str2 = hex_packet[28:30]

        if int(str1, 16) > 1500:
            FILE_VYPIS.write("Ethernet II\n")
            vnoreny_protokol = find_ether_type(hex_packet)

        elif str2.decode() == "ff" or str2.decode() == "FF":
            FILE_VYPIS.write("IEEE 802.3 - Raw\n")
            vnoreny_protokol = "IPX"

        elif str2.decode() == "aa" or str2.decode() == "AA":
            FILE_VYPIS.write("IEEE 802.3 s LLC a SNAP\n")
            vnoreny_protokol = find_lsap_type(hex_packet)

        else:
            FILE_VYPIS.write("IEEE 802.3 LLC\n")
            vnoreny_protokol = find_lsap_type(hex_packet)

        # Vypis adres (Zdrojovú a cieľovú fyzickú (MAC) adresu uzlov, medzi ktorými je rámec prenášaný)
        # Vypis zdrojovej MAC adresy
        FILE_VYPIS.write("Zdrojova MAC adresa: ")
        for i in range(6):
            if i != 5:
                FILE_VYPIS.write(chr(hex_packet[i * 2 + 12]) + chr(hex_packet[i * 2 + 13]) + " ")
            else:
                FILE_VYPIS.write(chr(hex_packet[i * 2 + 12]) + chr(hex_packet[i * 2 + 13]) + "\n")

        # Vypis cielovej MAC adresy
        FILE_VYPIS.write("Cielova MAC adresa: ")
        for i in range(6):
            if i != 5:
                FILE_VYPIS.write(chr(hex_packet[i * 2]) + chr(hex_packet[i * 2 + 1]) + " ")
            else:
                FILE_VYPIS.write(chr(hex_packet[i * 2]) + chr(hex_packet[i * 2 + 1]) + "\n")

        # Vypis vnoreneho protokola
        FILE_VYPIS.write(vnoreny_protokol + "\n")

        # Vypis celeho ramca
        for i in range(dlzka_ramca):    # Iterujem cez kazdy dajt
            str1 = hex_packet[i * 2]
            str2 = hex_packet[i * 2 + 1]

            if i % 16 == 15:                                # Pre posledny riadok
                FILE_VYPIS.write(chr(str1) + chr(str2) + "\n")
            elif i % 8 == 0 and i != 0 and i % 16 != 0:     # Pre oddelenie v prostriedku riadku
                FILE_VYPIS.write(" " + chr(str1) + chr(str2) + " ")
            elif i == dlzka_ramca - 1:                      # Pre osetrenie medzery za poslednym bajtom
                FILE_VYPIS.write(chr(str1) + chr(str2) + "\n\n")
            else:                                           # Pre vsetky ine
                FILE_VYPIS.write(chr(str1) + chr(str2) + " ")




FILE_VYPIS.write("Zoznam IP adries vsetkych odosielajucich uzlov: \n")
for adress in source_IPv4_adresses:
    FILE_VYPIS.write(adress + " " + str(source_IPv4_adresses[adress])+"\n")

most_often_IPv4adress = max(source_IPv4_adresses, key=source_IPv4_adresses.get)
FILE_VYPIS.write("\nIPv4 adresa uzla, ktora odoslala najvacsi pocet paketov: "+ str(most_often_IPv4adress) + " - " + str(source_IPv4_adresses[most_often_IPv4adress]) + " uzlov")

FILE_VYPIS.close()