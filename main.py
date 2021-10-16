# Napisal Stefan Otto Novak
import operator
from os import walk
from scapy.compat import bytes_hex
from scapy.utils import rdpcap


files = []
ETHER_types = {}
LSAP_types = {}
IPprotocols = {}
TCPports = {}
UDPports = {}
source_IPv4_adresses = {}
FILE_VYPIS = open(r"vypis.txt", "w")


def protocol_initialization():
    global ETHER_types, LSAP_types, IPprotocols, TCPports, UDPports  # Prikaz "global"
    FILE_PROTOKOLY = open('protokoly.txt', 'r')                      # aby zapisoval do glabalnych premennich

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


def transforme_to_IP_adress(hex_adres):
    adr1 = int(hex_adres[0:2], 16)
    adr2 = int(hex_adres[2:4], 16)
    adr3 = int(hex_adres[4:6], 16)
    adr4 = int(hex_adres[6:8], 16)
    str_adress = str(adr1) + "." + str(adr2) + "." + str(adr3) + "." + str(adr4)   # Vytori string adrese
    return str_adress


def add_IPv4_adress_to_list(hex_packet):
    global source_IPv4_adresses

    adress_str = transforme_to_IP_adress(hex_packet[52:60])  # Vytori string adrese

    if source_IPv4_adresses.__contains__(adress_str): # Ak adresu uz ma v slovniku, tak ikrementuje vyskity
        source_IPv4_adresses[adress_str] += 1
    else:
        source_IPv4_adresses[adress_str] = 1        # Ked adresa sa vyskitne prvykrat
    # Vypis zdrojovej a cielovej IP adrese


def find_ether_type(hex_packet):
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
    str1 = hex_packet[24:28]
    index_dictionary = int(str1.decode(), 16)

    if ETHER_types.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        if ETHER_types[index_dictionary] == "IPv4":
            add_IPv4_adress_to_list(hex_packet)
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

def find_IPv4_type(hex_protocol):
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
    index_dictionary = int(hex_protocol, 16)

    if IPprotocols.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        return IPprotocols[index_dictionary]
    else:
        return "Tento IP protokol nie je uvedeny v databaze"


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

        # Vypis cielovej a zdrojovej IP adrese
        if vnoreny_protokol == "IPv4":
            FILE_VYPIS.write("zdrojova IP adresa: " + transforme_to_IP_adress(hex_packet[52:60]) + "\n")
            FILE_VYPIS.write("cielova IP adresa: " + transforme_to_IP_adress(hex_packet[60:68]) + "\n")

            # Vypis IPv4 protokola
            FILE_VYPIS.write(find_IPv4_type(hex_packet[46:48]) + "\n")

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

# Zoradi IPv4 adresy zostupne podla poctu odoslanych ramcov
source_IPv4_adresses = dict(sorted(source_IPv4_adresses.items(), key = operator.itemgetter(1), reverse=True))

FILE_VYPIS.write("Zoznam IPv4 adries vsetkych odosielajucich uzlov: \n")
for adress in source_IPv4_adresses:
    FILE_VYPIS.write(adress +"\n") # ak chces vypisat aj pocet vyskitov pridaj + " " + str(source_IPv4_adresses[adress])

most_often_IPv4adress = max(source_IPv4_adresses, key=source_IPv4_adresses.get)
FILE_VYPIS.write("\nIPv4 adresa uzla, ktora odoslala najvacsi pocet paketov: "+ str(most_often_IPv4adress) + " - " + str(source_IPv4_adresses[most_often_IPv4adress]) + " uzlov")

FILE_VYPIS.close()