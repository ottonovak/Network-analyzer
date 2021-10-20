# Napisal Stefan Otto Novak
import operator
from os import walk
from scapy.compat import bytes_hex
from scapy.utils import rdpcap


files = []
ries_kom = 0
ETHER_types = {}
LSAP_types = {}
IPprotocols = {}
TCPports = {}
UDPports = {}
ICMP_ports = {}
ARP_ports = {}
source_IPv4_addresses = {}
HTTP_communications = {}
HTTPS_communications = {}
TELNET_communications = {}
SSH_communications = {}
FTP_riadiace_communications = {}
FTP_datove_communications = {}
DNS_communications = {}
ICMP_communications = {}
ARP_communications = {}
TFTP_communications = {}

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

        elif type_of_protocol == "ICMP":
            ICMP_ports[str1_int] = nested_protocol

    FILE_PROTOKOLY.close()


def add_communication(communications, index_frame, hex_packet):

    src_ip = transforme_to_IP_adress(hex_packet[52:60])
    dst_ip = transforme_to_IP_adress(hex_packet[60:68])

    src_port = int(hex_packet[68:72], 16)
    dst_port = int(hex_packet[72:76], 16)

    # kluc pre kazdu komunikaciu vytvoreny z str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port)
    src_key = str(src_ip) + str(dst_ip) + str(src_port) + str(dst_port)
    dst_key = str(dst_ip) + str(src_ip)+ str(dst_port) + str(src_port)

    if not communications.__contains__(src_key) and not communications.__contains__(dst_key):
        communications[src_key] = list()
        communications[src_key].append([index_frame, hex_packet])

    elif communications.__contains__(src_key):
        communications[src_key].append([index_frame, hex_packet])

    elif communications.__contains__(dst_key):
        communications[dst_key].append([index_frame, hex_packet])

    #for communication in communications:
        #print("ramec " + str(index_frame) + " -> komunikacia " + str(communication))


def transforme_to_IP_adress(hex_adres):
    adr1 = int(hex_adres[0:2], 16)
    adr2 = int(hex_adres[2:4], 16)
    adr3 = int(hex_adres[4:6], 16)
    adr4 = int(hex_adres[6:8], 16)
    str_adress = str(adr1) + "." + str(adr2) + "." + str(adr3) + "." + str(adr4)   # Vytori string adrese
    return str_adress


def write_TCP_type_port(hex_packet, index_frame):
    global ries_kom
    src_port = int(hex_packet[68:72], 16)
    dst_port = int(hex_packet[72:76], 16)

    if TCPports.__contains__(src_port):  # Preverii ak taky port bol vobec uvedeni databaze
        FILE_VYPIS.write(TCPports[src_port] + " -> " + str(src_port) + " \n")
        FILE_VYPIS.write("zdrojovy port: " + str(src_port) + "\n")
        FILE_VYPIS.write("cielovy port: " + str(dst_port) + "\n")

        if ries_kom == 0:
            if TCPports[src_port] == "HTTP":
                add_communication(HTTP_communications, index_frame, hex_packet)
            elif TCPports[src_port] == "HTTPS":
                add_communication(HTTPS_communications, index_frame, hex_packet)
            elif TCPports[src_port] == "DNS":
                add_communication(DNS_communications, index_frame, hex_packet)
            elif TCPports[src_port] == "TELNET":
                add_communication(TELNET_communications, index_frame, hex_packet)
            elif TCPports[src_port] == "SSH":
                add_communication(SSH_communications, index_frame, hex_packet)
            elif TCPports[src_port] == "FTP riadiace":
                add_communication(FTP_riadiace_communications, index_frame, hex_packet)
            elif TCPports[src_port] == "FTP datove":
                add_communication(FTP_datove_communications, index_frame, hex_packet)

    elif TCPports.__contains__(dst_port): # pripad ak je cielova adresa neajky TCP
        FILE_VYPIS.write(TCPports[dst_port] + " -> " + str(dst_port) + " \n")
        FILE_VYPIS.write("zdrojovy port: " + str(src_port) + "\n")
        FILE_VYPIS.write("cielovy port: " + str(dst_port) + "\n")

        if ries_kom == 0:
            if TCPports[dst_port] == "HTTP":
                add_communication(HTTP_communications, index_frame, hex_packet)
            elif TCPports[dst_port] == "HTTPS":
                add_communication(HTTPS_communications, index_frame, hex_packet)
            elif TCPports[dst_port] == "DNS":
                add_communication(DNS_communications, index_frame, hex_packet)
            elif TCPports[dst_port] == "TELNET":
                add_communication(TELNET_communications, index_frame, hex_packet)
            elif TCPports[dst_port] == "SSH":
                add_communication(SSH_communications, index_frame, hex_packet)
            elif TCPports[dst_port] == "FTP riadiace":
                add_communication(FTP_riadiace_communications, index_frame, hex_packet)
            elif TCPports[dst_port] == "FTP datove":
                add_communication(FTP_datove_communications, index_frame, hex_packet)

    else:
        FILE_VYPIS.write("Taky TCP ne je uvedeny, SRC port: "+ str(src_port) + " DST port: " + str(dst_port) + "\n")

def add_TFTP_communication(hex_packet, index_frame):
    src_ip = transforme_to_IP_adress(hex_packet[52:60])
    dst_ip = transforme_to_IP_adress(hex_packet[60:68])


    # kluc pre kazdu komunikaciu vytvoreny z str(src_ip) + str(dst_ip)
    src_key = str(src_ip) + str(dst_ip)
    dst_key = str(dst_ip) + str(src_ip)

    if not TFTP_communications.__contains__(src_key) and not TFTP_communications.__contains__(dst_key):
        TFTP_communications[src_key] = list()
        TFTP_communications[src_key].append([index_frame, hex_packet])

    elif TFTP_communications.__contains__(src_key):
        TFTP_communications[src_key].append([index_frame, hex_packet])

    elif TFTP_communications.__contains__(dst_key):
        TFTP_communications[dst_key].append([index_frame, hex_packet])


def write_UDP_type_port(hex_packet, index_frame):
    src_port = int(hex_packet[68:72], 16)
    dst_port = int(hex_packet[72:76], 16)


    if(UDPports.__contains__(dst_port)) and ries_kom == 0:
        FILE_VYPIS.write(str(UDPports[dst_port]) + "\n")
        add_TFTP_communication(hex_packet, index_frame)
        if UDPports[dst_port] == "TFTP" and ries_kom == 0:
            UDPports[src_port] = "TFTP"

    else:
        FILE_VYPIS.write("Tento UDP port nie je uvedeny v databaze " + str(dst_port) +"\n")

    FILE_VYPIS.write("zdrojovy port: " + str(int(hex_packet[68:72], 16)) + "\n")
    FILE_VYPIS.write("cielovy port: " + str(int(hex_packet[72:76], 16)) + "\n")

def write_ICMP_type_port(hex_packet, index_frame):
    global ries_kom

    type_of_ICMP = int(hex_packet[68:70], 16)
    src_port = int(hex_packet[68:72], 16)
    dst_port = int(hex_packet[72:76], 16)


    if ICMP_ports.__contains__(type_of_ICMP) and ries_kom == 0:  # Preverii ak taky port bol vobec uvedeni databaze
        FILE_VYPIS.write(ICMP_ports[type_of_ICMP] + " -> " + str(type_of_ICMP) + " \n")

        if ries_kom == 0:

            src_ip = transforme_to_IP_adress(hex_packet[52:60])
            dst_ip = transforme_to_IP_adress(hex_packet[60:68])

            # kluc pre kazdu komunikaciu vytvoreny z str(src_ip) + str(dst_ip)
            src_key = str(src_ip) + str(dst_ip)
            dst_key = str(dst_ip) + str(src_ip)

            if not ICMP_communications.__contains__(src_key) and not ICMP_communications.__contains__(dst_key):
                ICMP_communications[src_key] = list()
                ICMP_communications[src_key].append([index_frame, hex_packet])

            elif ICMP_communications.__contains__(src_key):
                ICMP_communications[src_key].append([index_frame, hex_packet])

            elif ICMP_communications.__contains__(dst_key):
                ICMP_communications[dst_key].append([index_frame, hex_packet])

            #for communication in ICMP_communications:
            #    print("ramec " + str(index_frame) + " -> komunikacia " + str(communication))


    else:
        if ries_kom == 0:
            FILE_VYPIS.write("Taky ICMP ne je uvedeny v databaze: " + str(type_of_ICMP) + "\n")


def add_source_IPv4_adress_to_list(hex_packet):
    global source_IPv4_addresses

    adress_str = transforme_to_IP_adress(hex_packet[52:60])  # Vytori string adrese
    if source_IPv4_addresses.__contains__(adress_str): # Ak adresu uz ma v slovniku, tak ikrementuje vyskity
        source_IPv4_addresses[adress_str] += 1
    else:
        source_IPv4_addresses[adress_str] = 1        # Ked adresa sa vyskitne prvykrat


def add_ARP_communication(hex_packet, index_frame):
    type_of_ARP = ""
    src_ip = ""
    src_MAC = ""
    dst_ip = ""

    if hex_packet[42:44].decode() == "01":
        type_of_ARP = "request"
    else:
        type_of_ARP = "reply"

    if type_of_ARP == "request" or type_of_ARP == "reply":
        if type_of_ARP == "request":
            src_ip = transforme_to_IP_adress(hex_packet[56:64])
            src_MAC = str(hex_packet[12:24].decode())
            dst_ip = transforme_to_IP_adress(hex_packet[76:84])
        else:
            dst_ip = transforme_to_IP_adress(hex_packet[56:64])
            src_MAC = str(hex_packet[0:12].decode())
            src_ip = transforme_to_IP_adress(hex_packet[76:84])

        key = str(src_ip) + str(src_MAC) + str(dst_ip)

        if not ARP_communications.__contains__(key):
            ARP_communications[key] = list()
        ARP_communications[key].append([index_frame, hex_packet])


def find_ether_type(hex_packet, index_frame):
    global ries_kom
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
    str1 = hex_packet[24:28]
    index_dictionary = int(str1.decode(), 16)

    if ETHER_types.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        if ETHER_types[index_dictionary] == "IPv4" and ries_kom == 0:
            add_source_IPv4_adress_to_list(hex_packet)

        if ETHER_types[index_dictionary] == "ARP" and ries_kom == 0:
            if hex_packet[42:44].decode() == "01":
                FILE_VYPIS.write("ARP request\n")
            elif hex_packet[42:44].decode() == "02":
                FILE_VYPIS.write("ARP reply\n")
            add_ARP_communication(hex_packet, index_frame)

        if ETHER_types[index_dictionary] == "ARP" and ries_kom == 1:
            if hex_packet[42:44].decode() == "01":
                FILE_VYPIS.write("ARP request\n")
            elif hex_packet[42:44].decode() == "02":
                FILE_VYPIS.write("ARP reply\n")

        return ETHER_types[index_dictionary]
    else:
        return "Tento EtherType nie je uvedeny v databaze"


def find_lsap_type(hex_packet):
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
    str2 = hex_packet[28:30]
    index_dictionary = int(str2.decode(), 16)

    if LSAP_types.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        return LSAP_types[index_dictionary]
    else:
        return "Tento LSAP nie je uvedeny v databaze"


def write_IPv4_type_port(hex_packet, index_frame):
    # Hlada v slovniku nazov protokolu (ktore cerpal z databaze/textaku "protokoly.txt")
# todo hladaj
    hex_protocol = hex_packet[46:48]
    index_dictionary = int(hex_protocol, 16)

    if IPprotocols.__contains__(index_dictionary):  # Preverii ak taky protokol bol vobec uvedeni databaze
        FILE_VYPIS.write(IPprotocols[index_dictionary] + "\n")
        if IPprotocols[index_dictionary] == "TCP":
            write_TCP_type_port(hex_packet, index_frame)

        elif IPprotocols[index_dictionary] == "UDP":
            write_UDP_type_port(hex_packet, index_frame)

        elif IPprotocols[index_dictionary] == "ICMP":
            write_ICMP_type_port(hex_packet, index_frame)
    else:
        FILE_VYPIS.write("Tento typ IP protokolu nie je uvedeny v databaze\n")


def read_files():
    for (dirpath, dirnames, filenames) in walk("./subory_na_analyzu"):
        # Program cita vsetky subory z priecinku "subory_na_analyzu"
        files.extend(filenames)
    return files


def write_type_of_frame(hex_packet, index_frame):
    # Vypis typu ramca (– Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 - Raw)
    str1 = hex_packet[24:28]
    str2 = hex_packet[28:30]
    vnoreny_protokol = ""

    if int(str1, 16) > 1500:
        FILE_VYPIS.write("Ethernet II\n")
        vnoreny_protokol = find_ether_type(hex_packet, index_frame)

    elif str2.decode() == "ff" or str2.decode() == "FF":
        FILE_VYPIS.write("IEEE 802.3 - Raw\n")
        vnoreny_protokol = "IPX"

    elif str2.decode() == "aa" or str2.decode() == "AA":
        FILE_VYPIS.write("IEEE 802.3 s LLC a SNAP\n")
        vnoreny_protokol = find_lsap_type(hex_packet)

    else:
        FILE_VYPIS.write("IEEE 802.3 LLC\n")
        vnoreny_protokol = find_lsap_type(hex_packet)

    return vnoreny_protokol


def write_MAC_adress(hex_packet, x):   # x znazornuje bit odkial zacne adresa cilova/zdrojova
    if x == 12:
        FILE_VYPIS.write("Zdrojova MAC adresa: ")
    elif x == 0:
        FILE_VYPIS.write("Cielova MAC adresa: ")

    for i in range(6):
        if i != 5:
            FILE_VYPIS.write(chr(hex_packet[i * 2 + x]) + chr(hex_packet[i * 2 + 1 + x]) + " ")
        else:
            FILE_VYPIS.write(chr(hex_packet[i * 2 + x]) + chr(hex_packet[i * 2 + + 1 + x]) + "\n")


def write_entire_packet(hex_packet, dlzka_ramca):
    for i in range(dlzka_ramca):  # Iterujem cez kazdy dajt
        str1 = hex_packet[i * 2]
        str2 = hex_packet[i * 2 + 1]

        if i % 16 == 15:  # Pre posledny riadok
            FILE_VYPIS.write(chr(str1) + chr(str2) + "\n")
        elif i % 8 == 0 and i != 0 and i % 16 != 0:  # Pre oddelenie v prostriedku riadku
            FILE_VYPIS.write(" " + chr(str1) + chr(str2) + " ")
        elif i == dlzka_ramca - 1:  # Pre osetrenie medzery za poslednym bajtom
            FILE_VYPIS.write(chr(str1) + chr(str2) + "\n\n")
        else:  # Pre vsetky ine
            FILE_VYPIS.write(chr(str1) + chr(str2) + " ")


def write_frame_efectiv(frame):
    index_frame = frame[0]
    packet = frame[1]
    # print(index_frame, end=" ")
    # print(packet)
    # Vypis ramca (Poradové číslo rámca v analyzovanom súbore)
    FILE_VYPIS.write("ramec " + str(index_frame) + "\n")
    hex_packet = packet

    # Vypis dlzonk (Dĺžku rámca v bajtoch poskytnutú pcap API a dĺžku tohto rámca prenášaného po médiu)
    dlzka_ramca = int(len(packet) / 2)
    FILE_VYPIS.write("dlzka ramca poskytnuta pcap API - " + str(dlzka_ramca) + "B\n")
    FILE_VYPIS.write("dlzka ramca prenasaneho po mediu - " + str(max(64, dlzka_ramca + 4)) + "B\n")

    # Vypis typu ramca (– Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 - Raw)
    vnoreny_protokol = write_type_of_frame(hex_packet, index_frame)

    # Vypis adres (Zdrojovú a cieľovú fyzickú (MAC) adresu uzlov, medzi ktorými je rámec prenášaný)
    write_MAC_adress(hex_packet, 12)  # od 12. bit =  zdrojova MAC adresa
    write_MAC_adress(hex_packet, 0)  # od 0. bit =  cielova MAC adresa

    # Vypis vnoreneho protokola
    FILE_VYPIS.write(vnoreny_protokol + "\n")

    # Vypis cielovej a zdrojovej IP adrese
    if vnoreny_protokol == "IPv4":
        FILE_VYPIS.write("zdrojova IP adresa: " + transforme_to_IP_adress(hex_packet[52:60]) + "\n")
        FILE_VYPIS.write("cielova IP adresa: " + transforme_to_IP_adress(hex_packet[60:68]) + "\n")
        write_IPv4_type_port(hex_packet, index_frame)  # Vypis IPv4 protokolov

    # Vypis celeho ramca
    write_entire_packet(hex_packet, dlzka_ramca)


def write_frame(packets):
    x = 0

    # ak su viac nez 19, vypise prve 10 a posledne 10
    if len(packets) > 19:
        x = 0
        for frame in packets:
            x += 1
            if x > 10:
                break
            write_frame_efectiv(frame)

         # poslende 10 ramce
        x = 0

        for frame in packets[len(packets)-20:]:
            x += 1
            if x > 10:
                break
            write_frame_efectiv(frame)

    # ak su menej nez 20, vypise vsetky
    if len(packets) < 20:
        dlzka = len(packets)

        for frame in packets:
            x += 1
            if x > dlzka:
                break
            write_frame_efectiv(frame)


def analyze_files(files):
    global source_IPv4_addresses
    for filename in files:

        FILE_VYPIS.write("\n<<<<<<<< Analyzujes subor " + filename + " >>>>>>>>\n")
        packets = rdpcap(f"./subory_na_analyzu/{filename}")
        index_frame = 0

        for packet in packets:
            index_frame += 1
            # Vypis ramca (Poradové číslo rámca v analyzovanom súbore)
            FILE_VYPIS.write("ramec " + str(index_frame) + "\n")
            hex_packet = bytes_hex(packet)
            # Vypis dlzonk (Dĺžku rámca v bajtoch poskytnutú pcap API a dĺžku tohto rámca prenášaného po médiu)
            dlzka_ramca = len(packet)
            FILE_VYPIS.write("dlzka ramca poskytnuta pcap API - " + str(dlzka_ramca) + "B\n")
            FILE_VYPIS.write("dlzka ramca prenasaneho po mediu - " + str(max(64, dlzka_ramca + 4)) + "B\n")

            # Vypis typu ramca (– Ethernet II, IEEE 802.3 (IEEE 802.3 s LLC, IEEE 802.3 s LLC a SNAP, IEEE 802.3 - Raw)
            vnoreny_protokol = write_type_of_frame(hex_packet, index_frame)

            # Vypis adres (Zdrojovú a cieľovú fyzickú (MAC) adresu uzlov, medzi ktorými je rámec prenášaný)
            write_MAC_adress(hex_packet, 12) # od 12. bit =  zdrojova MAC adresa
            write_MAC_adress(hex_packet, 0)  # od 0. bit =  cielova MAC adresa

            # Vypis vnoreneho protokola
            FILE_VYPIS.write(vnoreny_protokol + "\n")

            # Vypis cielovej a zdrojovej IP adrese
            if vnoreny_protokol == "IPv4":
                FILE_VYPIS.write("zdrojova IP adresa: " + transforme_to_IP_adress(hex_packet[52:60]) + "\n")
                FILE_VYPIS.write("cielova IP adresa: " + transforme_to_IP_adress(hex_packet[60:68]) + "\n")
                write_IPv4_type_port(hex_packet, index_frame)    # Vypis IPv4 protokola

            # Vypis celeho ramca
            write_entire_packet(hex_packet, dlzka_ramca)



    # Zoradi IPv4 adresy zostupne podla poctu odoslanych ramcov
    source_IPv4_addresses = dict(sorted(source_IPv4_addresses.items(), key = operator.itemgetter(1), reverse=True))

    FILE_VYPIS.write("Zoznam IPv4 adries vsetkych odosielajucich uzlov:\n     Adresa      Vyskitnutia\n")
    for adress in source_IPv4_addresses:
        FILE_VYPIS.write(adress + "  -  " + str(source_IPv4_addresses[adress]) + "\n") # ak chces vypisat aj pocet vyskitov pridaj + " " + str(source_IPv4_adresses[adress])

    most_often_IPv4adress = max(source_IPv4_addresses, key=source_IPv4_addresses.get)
    FILE_VYPIS.write("\nIPv4 adresa uzla, ktora odoslala najvacsi pocet paketov: " + str(most_often_IPv4adress) + " - " + str(source_IPv4_addresses[most_often_IPv4adress]) + " uzlov")


def find_start_communication(commun, communications):
    # Kontrola 3 way handshake
    kolky_ramec = 0
    sw1 = 0
    sw2 = 0
    sw3_zacala_komunikacia = 0

    for ramec in communications[commun]:
        bin_flag = bin(int(ramec[1][92:96].decode(), 16))
        #print("  SYN = " + bin_flag[-2] + " ACK = "+ bin_flag[-5] + " RST = " + bin_flag[-3] + " FIN = " + bin_flag[-1])

        # Ked sa uz naslo
        if sw3_zacala_komunikacia == 1:
            return ["complete", kolky_ramec + 1]  # returnujem stav a nasledovny ramec

        if sw1 == 0:  # SYN
            if bin_flag[-2] == "1":
                sw1 = 1
                continue

        if sw1 == 1 and sw2 == 0:   # SYN a zaroven ACK
            if bin_flag[-2] == "1" and bin_flag[-5] == "1":
                sw2 = 1
                continue

        if sw2 == 1 and sw3_zacala_komunikacia == 0: # ACK
            if bin_flag[-5] == "1":
                sw3_zacala_komunikacia = 1
        kolky_ramec += 1

    return ["incomplete", kolky_ramec - 1]


def find_end_communication(commun, ramec_pokracovat, communications):
    sw4 = 0
    sw5 = 0
    sw6 = 0
    sw7_ukoncena_komunikacia = 0

    for ramec in communications[commun][ramec_pokracovat:]:
        bin_flag = bin(int(ramec[1][92:96].decode(), 16))

        # ukoncenie komunikacie RST
        if sw7_ukoncena_komunikacia == 0:  # RST
            if bin_flag[-3] == "1":
                sw7_ukoncena_komunikacia = 1
                return "complete"


        # ukoncenie komuniakcie - pripad FIN-ACK-FIN-ACK
        if sw4 == 0 and sw7_ukoncena_komunikacia == 0:  # FIN
            if bin_flag[-1] == "1":
                sw4 = 1
                continue

        if sw4 == 1 and sw5 == 0 and sw7_ukoncena_komunikacia == 0:  # ACK
            if bin_flag[-5] == "1":
                sw5 = 1
                continue

        if sw5 == 1 and sw7_ukoncena_komunikacia == 0:  # FIN
            if bin_flag[-1] == "1":
                sw6 = 1
                continue

        if sw6 == 1 and sw7_ukoncena_komunikacia == 0:  # ACK
            if bin_flag[-5] == "1":
                sw7_ukoncena_komunikacia = 1
                return "complete"


        # RST ukoncena komunikacia pripad FIN-ACK-RST
        if sw5 == 1 and sw7_ukoncena_komunikacia == 0:
            if bin_flag[-3] == "1":
                sw7_ukoncena_komunikacia = 1
                return "complete"

    return "incomplete"


def write_complete_and_incomplete_TCP_communication(communications, protocol_type):
    uspesna_vypisana_kompletna = 0
    uspesna_vypisana_nekompletna = 0

    for commun in communications:
        start = find_start_communication(commun, communications)
        if start[0] == "complete":
            print("3wh")
            ramec_pokracovat = start[1]
            end = find_end_communication(commun, ramec_pokracovat,communications)
            if end == "complete":
                print("COMPLETE")
                if uspesna_vypisana_kompletna == 0:
                    FILE_VYPIS.write("\nuspesna " + protocol_type + " komunikacia----------------------------------\n")
                    write_frame(communications[commun])
                    uspesna_vypisana_kompletna = 1

            elif end == "incomplete":
                print("NOT C")
                if uspesna_vypisana_nekompletna == 0:
                    FILE_VYPIS.write("\nNEuspesna " + protocol_type + " komunikacia--------------------------------\n")
                    write_frame(communications[commun])
                    uspesna_vypisana_nekompletna = 1


def write_ICMP_ARP_communications(communications, type_of_comm):

    x = 0
    for commun in communications:
        x += 1
        print(x)
        FILE_VYPIS.write("\n" + str(x) + ". "+ str(type_of_comm)+" komunikacia----------------------------------------\n")
        for frame in communications[commun]:
            write_frame_efectiv(frame)




if __name__ == "__main__":
    FILE_VYPIS = open(r"vypis.txt", "w")
    protocol_initialization()
    files = read_files()
    analyze_files(files)
    FILE_VYPIS.close()

    FILE_VYPIS = open(r"vypis_komunikacia.txt", "w")
    ries_kom = 1

    print("HTTP komunikacie")
    write_complete_and_incomplete_TCP_communication(HTTP_communications, "HTTP")
    print("HTTPS komunikacie")
    write_complete_and_incomplete_TCP_communication(HTTPS_communications, "HTTPS")
    print("TELNET komunikacie")
    write_complete_and_incomplete_TCP_communication(TELNET_communications, "TELNET")
    print("SSH komunikacie")
    write_complete_and_incomplete_TCP_communication(SSH_communications, "SSH")
    print("FTP riadiace komunikacie")
    write_complete_and_incomplete_TCP_communication(FTP_riadiace_communications, "FTP riadiace")
    print("FTP datove komunikacie")
    write_complete_and_incomplete_TCP_communication(FTP_datove_communications, "FTP datove")
    print("ICMP komunikacie")
    write_ICMP_ARP_communications(ICMP_communications, "ICMP")
    print("ARP komunikacie")
    write_ICMP_ARP_communications(ARP_communications, "ARP")
    print("TFTP komunikacie")
    write_ICMP_ARP_communications(TFTP_communications, "TFTP")

    FILE_VYPIS.close()