from . import utils, LesExceptions, dictionnaires
import copy
"""
import utils
import LesExceptions
import copy
import dictionnaires
"""
def teste():
    print("coucou")
    return 

def toListeTrame(fichier):
    liste_Trame_invalide = []
    liste_ligne_incomplete = []
    liste_trame_en_octet = []
    lignes_origine = fichier.readlines()
    
    lignes_origine = [ i.decode() for i in lignes_origine ]


    lignes = copy.deepcopy(lignes_origine)
    l = 0
    while l < len(lignes): #test les normes des offsets et enlever des lignes de texte entrelacées
        if not utils.ligne_valide_simple(lignes[l]):
            lignes.remove(lignes[l]) #Nous enlevons les lignes contenant offset invalids
        else:
            l += 1
    liste_Trame = utils.divise_en_trames(lignes)
    for t in liste_Trame: #enlever les trames dont offsets ne sont pas cohérents entre eux
        coherence, nbOctet = utils.test_coherence_offset(t, lignes_origine)
        if coherence:
            l_octet, l_incomplete = utils.trame_en_liste_octet(t, nbOctet[0], lignes_origine)
            if l_incomplete == []: #Si la trame est complète
                liste_trame_en_octet.append(l_octet)
            else: #Sinon, nous recuppèrons les positions des lignes incomplètes
                for index in l_incomplete:
                    liste_ligne_incomplete.append(index)
        else:
            liste_Trame_invalide.append(nbOctet)
    if liste_Trame_invalide != []:
        raise  LesExceptions.TrameException(liste_Trame_invalide)
    if liste_ligne_incomplete != []:
        raise LesExceptions.LigneException(liste_ligne_incomplete)
    return liste_trame_en_octet

def Ethernet(trame):
    """" ----------Couche Ethernet-------------"""
    s = ""
    adresseDes = ":".join(trame[0:6])
    adresseSource = ":".join(trame[6:12])
    type = "0x" + "".join(trame[12:14])
    EthernetType = ""
    s+="Ethernet II, Src: ({}), Dst: ({})\n".format(adresseSource, adresseDes)
    s+="\tDestination: ({})\n".format(adresseDes)
    s+="\tSource: ({})\n".format(adresseSource)
    if type == "0x0800":
        EthernetType = "IPv4"
    elif type == "0x86dd":
        EthernetType = "IPv6"
    elif type == "0x0806":
        EthernetType = "ARP"
    s+="\tType: {} ({})\n".format(EthernetType, type)
    return s

def IP(trame):
    """
    :param trame: la trame
    :return: (string, longeur de l'entete d'IP, isUDP)
    """
    """"1ere ligne TP"""
    s=""
    version = trame[0][0]
    header_length = trame[0][1]
    TOS = trame[1]
    Total_length = utils.hex_to_dec(trame[2] + trame[3])
    """"2eme ligne TP"""
    trameCopie = trame[4:]  # enlever 1ere ligne
    identifiant = trame[0] + trame[1]
    flags = trameCopie[2]
    flag_3bits = utils.hex_to_binaire(trameCopie[2][0], 4)[:3]
    R = "\t{}... .... = Reserved bit: ".format(flag_3bits[0])
    R += "Set\n" if flag_3bits[0] == '1' else "Not set\n"
    DF = "\t.{}.. .... = Reserved bit: ".format(flag_3bits[1])
    DF += "Set\n" if flag_3bits[1] == '1' else "Not set\n"
    MF = "\t..{}. .... = Reserved bit: ".format(flag_3bits[2])
    MF += "Set\n" if flag_3bits[2] == '1' else "Not set\n"
    frag_offset = int(utils.hex_to_binaire(trameCopie[2][0], 4)[-1] + utils.hex_to_binaire(trameCopie[2][1], 4) + utils.hex_to_binaire(
        trameCopie[3], 8), 2)  # transformer en binaire, puis de binaire en decimal
    """"3eme ligne TP"""
    trameCopie = trameCopie[4:]  # enlever 2eme ligne
    TTL = utils.hex_to_dec(trameCopie[0])
    protocol = utils.hex_to_dec(trameCopie[1])
    protocol_nom = "TCP" if protocol == 6 else ("ICMP" if protocol == 1 else "UDP")
    header_checksum = trameCopie[2] + trameCopie[3]
    """"4eme ligne TP"""
    trameCopie = trameCopie[4:]  # enlever 3eme ligne
    source_adresse = ".".join(str(utils.hex_to_dec(n)) for n in trameCopie[0:4])
    """"5eme ligne TP"""
    trameCopie = trameCopie[4:]  # enlever 4eme ligne
    des_adresse = ".".join(str(utils.hex_to_dec(n)) for n in trameCopie[0:4])
    trameCopie = trameCopie[4:]  # enlever la couche IP
    """"Affichage couche IP"""
    s+="Internet Protocol Version {}, Src: {}, Dst: {}\n".format(version, source_adresse, des_adresse)
    s+="\t{} .... = Version: {}\n".format(utils.hex_to_binaire(version, 4), version)
    s+="\t.... {} = Header Length: {} bytes ({})\n".format(utils.hex_to_binaire(header_length, 4),
                                                            4 * int(utils.hex_to_dec(header_length)), header_length)
    s+="\tDifferentiated Services Field: 0x{}\n".format(TOS)
    s+="\tTotal Length: {}\n".format(Total_length)
    s+="\tIdentification: 0x{} ({})\n".format(identifiant, utils.hex_to_dec(identifiant))
    s+="\tFlags: 0x{}\n".format(flags)
    s+=R
    s+=DF
    s+=MF
    s+="\tFragment Offset: {}\n".format(frag_offset)
    s+="\tTime to Live: {}\n".format(TTL)
    s+="\tProtocol: {} ({})\n".format(protocol_nom, protocol)
    s+="\tHeader Checksum: 0x{}\n".format(header_checksum)
    s+="\tSource Address: {}\n".format(source_adresse)
    s+="\tDestination Address: {}\n".format(des_adresse)
    return s, 4*int(utils.hex_to_dec(header_length)), protocol == 17

def UDP(trame):
    """
        return: (string, 1) Si DHCP, (string, 2) Si DNS, (string, 0) sinon
    """
    s=""
    source_port = trame[0] + trame[1]
    des_port = trame[2] + trame[3]
    lenght = trame[4] + trame[5]
    check_sum = trame[6] + trame[7]
    S_P = utils.hex_to_dec(source_port)
    D_P = utils.hex_to_dec(des_port)
    s+="User Datagram Protocol, Src Port: {}, Dst Port: {}\n".format(S_P, D_P)
    s+="\tSource Port: {}\n".format(S_P)
    s+="\tDestination Port: {}\n".format(D_P)
    s+="\tLength: {}\n".format(utils.hex_to_dec(lenght))
    s+="\tChecksum: 0x{}\n".format(check_sum)
    s+="\tUDP payload ({} bytes)\n".format(len(trame[8:]))
    return (s, 1) if (S_P == 67 or D_P == 67) else ((s, 2) if (S_P == 53 or D_P == 53) else (s, 0))

def DHCP(trame):
    s=""
    mess_type = "\tMessage type: "
    mess_type = mess_type + " Boot Request (1)\n" if (utils.hex_to_dec(trame[0]) == 1) else mess_type + " Boot Reply (2)\n"
    hw_type = "\tHardware type: {} (0x{})\n".format(dictionnaires.HW_type[utils.hex_to_dec(trame[1])], trame[1])
    titre = "Dynamic Host Configuration Protocol "
    titre = titre + "(Request)\n" if (utils.hex_to_dec(trame[0]) == 1) else titre + "(Reply)\n"
    hw_address_len = "\tHardware address length: {}\n".format(utils.hex_to_dec(trame[2]))
    hop = "\tHops: {}\n".format(utils.hex_to_dec(trame[3]))
    Transaction_ID = "\tTransaction ID: 0x" + "".join(trame[4:8])+"\n"
    Second_eslapsed = "\tSeconds elapsed: {}\n".format(utils.hex_to_dec("".join(trame[8:10])))
    bootp_flags = "Unicast" if utils.hex_to_binaire(trame[10], 8)[0] == '0' else "Broadcast"
    client_ip = "\tClient IP address: " + ".".join(list(map(lambda x: str(utils.hex_to_dec(x)), trame[12:16])))+"\n"
    your_client_ip = "\tYour (client) IP address: " + ".".join(
        list(map(lambda x: str(utils.hex_to_dec(x)), trame[16:20])))+"\n"
    next_sv_ip = "\tNext server IP address: " + ".".join(list(map(lambda x: str(utils.hex_to_dec(x)), trame[20:24])))+"\n"
    relay_ip = "\tRelay agent IP address: " + ".".join(list(map(lambda x: str(utils.hex_to_dec(x)), trame[24:28])))+"\n"
    client_mac = "\tClient MAC address: {} ({})\n".format(":".join(trame[28:34]), ":".join(trame[28:34]))
    client_padding = "\tClient hardware address padding: {}\n".format("".join(trame[34:44]))
    magic_cookie = "\tMagic cookie: " + (
        "DHCP\n" if trame[236] == "63" and trame[237] == "82" and trame[238] == "53" and trame[
            239] == "63" else "Undefine\n")
    s = s+\
        titre\
        +mess_type\
        +hw_type\
        +hw_address_len\
        +hop\
        +Transaction_ID\
        +Second_eslapsed
    s+="\tBootp flags: 0x{}{} ({})\n".format(trame[10], trame[11], bootp_flags)
    s+="\t\t{}... .... .... .... = Broadcast flag: {}\n".format(utils.hex_to_binaire(trame[10], 8)[0], bootp_flags)
    s+="\t\t.{} {} {} {} = Reserved flags: 0x{}\n".format(
        utils.hex_to_binaire(trame[10], 8)[1:4],
        utils.hex_to_binaire(trame[10], 8)[4:8],
        utils.hex_to_binaire(trame[11], 8)[0:4],
        utils.hex_to_binaire(trame[11], 8)[4:8],
        "".join(trame[10:12]))
    s=s+client_ip\
      +your_client_ip\
      +next_sv_ip\
      +relay_ip\
      +client_mac\
      +client_padding\
      +magic_cookie
    option = trame[240:]
    i = 0
    while i < len(option):
        name = utils.hex_to_dec(option[i])
        op_len = utils.hex_to_dec(option[i + 1])
        i = i + 2 + op_len
        s+="\tOption: ({}) {}\n".format(name, dictionnaires.DHCP_option[name])
        if name == 255:
            break
    return s

def DNS(trame):
    s=""
    transaction_ID = "\tTransaction ID: 0x{}\n".format("".join(trame[:2]))
    flags = utils.hex_to_binaire("".join(trame[2:4]), 16)
    reponse = "\t\t{}... .... .... .... = Reponse: Message is a {}\n".format(flags[0], ("response" if flags[0] == '1' else "query"))
    opcode = "\t\t.{} {}... .... .... = Opcode: {} ({})\n".format(flags[1:4], flags[4], dictionnaires.DNS_opcode[int(flags[1:5], 2)], int(flags[1:5], 2))
    titre = "Domain Name System ({})\n".format("response" if flags[0] == '1' else "query")
    t_flags = "\tFlags: 0x{} {} {}\n".format("".join(trame[2:4]), dictionnaires.DNS_opcode[int(flags[1:5], 2)], "response" if flags[0] == '1' else "query")
    authoriative = "\t\t.... .{}.. .... .... = Authoritative: Server {} an authority for domain\n".format(flags[5], "is" if flags[5] == '1' else "is not")
    truncated = "\t\t.... ..{}. .... .... = Truncated: Message {} truncated\n".format(flags[6], "is" if flags[6] == '1' else "is not")
    rec_desired = "\t\t.... ...{} .... .... = Recursion desired: {} query recursively\n".format(flags[7], "Do" if flags[7] == '1' else "Dont'do")
    rec_available = "\t\t.... .... {}... .... = Recursion available: Server {} do recursive queries\n".format(flags[8], "can" if flags[8] == '1' else "can not")
    Z = "\t\t.... .... .0.. .... = Z: reserved (0)\n"
    ans_auth = "\t\t.... .... ..{}. .... = Answer authenticated: Answer/authority portion {} authenticated by the server\n".format(flags[10], "was" if flags[10] == '1' else "was not")
    non_auth_data = "\t\t.... .... ...{} .... = Non-authenticated data: {}\n".format(flags[11], "Acceptable" if flags[11] == '1' else "Unacceptable")
    rep_code = "\t\t.... .... .... {} = Reply code: {}\n".format(flags[12:], dictionnaires.DNS_replycode[int(flags[12:], 2)])
    question = "\tQuestions: {}\n".format(utils.hex_to_dec("".join(trame[4:6])))
    answer = "\tAnswer RRs: {}\n".format(utils.hex_to_dec("".join(trame[6:8])))
    auth_rr = "\tAuthority RRs: {}\n".format(utils.hex_to_dec("".join(trame[8:10])))
    add_rr = "\tAdditional RRs: {}\n".format(utils.hex_to_dec("".join(trame[10:12])))
    s=s+titre\
      +transaction_ID\
      +t_flags\
      +reponse\
      +opcode\
      +authoriative\
      +truncated\
      +rec_desired\
      +rec_available\
      +Z\
      +ans_auth\
      +non_auth_data\
      +rep_code\
      +question\
      +answer\
      +auth_rr\
      +add_rr
    nb_Q = utils.hex_to_dec("".join(trame[4:6]))
    nb_A = utils.hex_to_dec("".join(trame[6:8]))
    trame_tmp = trame[12:] #enlever les premiers 12 octets
    s+="Queries\n"
    dic = {}
    cpt = 12 #debut les questions
    dic = {} #Pour retrouver le nom de la question pour les answers
    for i in range(nb_Q):
        name_h = ""
        for j in range(len(trame_tmp)):
            if trame_tmp[j] == "00":
                break
            name_h += trame_tmp[j]
        name_h = name_h[2:]
        name = ""
        for i in range(0, len(name_h), 2):
            l = name_h[i] + name_h[i + 1]
            if utils.hex_to_dec(l) >= 97 and utils.hex_to_dec(l) <= 122:
                name += bytes.fromhex(l).decode("ASCII")
            else:
                name += "."
        type = "".join(trame_tmp[len(name)+2:len(name)+4])
        class_q = "".join(trame_tmp[len(name)+4:len(name)+6])
        s+="\t{}: type {}, class {}\n".format(name, dictionnaires.DNS_type[utils.hex_to_dec(type)], dictionnaires.DNS_class[utils.hex_to_dec(class_q)])
        s+="\t\tName: {}\n".format(name)
        s+="\t\t[Name Length: {}]\n".format(len(name))
        s+="\t\t[Label Count: {}]\n".format(name.count('.') + 1)  # nb colonnes séparées par .
        s+="\t\tType: {}\n".format(dictionnaires.DNS_type[utils.hex_to_dec(type)])
        s+="\t\tClass: {} (0x{})\n".format(dictionnaires.DNS_class[utils.hex_to_dec(class_q)], class_q)
        dic[cpt] = name
        cpt = cpt+len(name)+6 if i < nb_Q else cpt #passer a l'indice du nom suivant
        trame_tmp = trame_tmp[len(name)+6:]
    s+="Answers\n"
    for i in range(nb_A):
        ind = utils.hex_to_dec(trame_tmp[1])
        type = "".join(trame_tmp[2:4])
        class_a = "".join(trame_tmp[4:6])
        ttl = "".join(trame_tmp[6:10])
        data_len = "".join(trame_tmp[10:12])
        s+="\t{}: type {}, class {}, addr {}\n".format(dic[ind], dictionnaires.DNS_type[utils.hex_to_dec(type)], dictionnaires.DNS_class[utils.hex_to_dec(class_a)], ".".join(list(map(lambda  x: str(utils.hex_to_dec(x)), trame_tmp[12:16]))))
        s+="\t\tName: {}\n".format(dic[ind])
        s+="\t\tType: {}\n".format(dictionnaires.DNS_type[utils.hex_to_dec(type)])
        s+="\t\tClass: {}\n".format(dictionnaires.DNS_class[utils.hex_to_dec(class_a)])
        s+="\t\tTime to live: {} ({})\n".format(utils.hex_to_dec(ttl), utils.sec_to_hms(utils.hex_to_dec(ttl)))
        s+="\t\tData length: {}\n".format(utils.hex_to_dec(data_len))
        s+="\t\tAddress: {}\n".format(".".join(list(map(lambda  x: str(utils.hex_to_dec(x)), trame_tmp[12:16]))))
        trame_tmp = trame_tmp[16:]
    return s

def analyse(listeTrame):
    liste_info = []
    for trame in listeTrame:
        dic = {}

        s=""
        trameCopie = copy.deepcopy(trame)
        trameCopie = list((map(lambda x: x.lower().strip("\n"), trameCopie)))  # passer tous les octets en minuscule
        resEthernet=Ethernet(trameCopie)
        """" ----------Couche IP-------------"""
        """"1ere ligne TP"""
        trameCopie = trameCopie[14:] #enlever les octets de la couche Ethernet
        resIP, header_IP_len, isUDP = IP(trameCopie)
        trameCopie = trameCopie[header_IP_len:]
        res_couche_app=""
        resUDP=""
        if isUDP:
            resUDP, type = UDP(trameCopie)
            trameCopie = trameCopie[8:] #enlever UDP
            if type == 1: #DHCP
                res_couche_app=DHCP(trameCopie)
                dic["DHCP"] = res_couche_app
                dic["DNS"] = ""
            elif type == 2: #DNS
                res_couche_app=DNS(trameCopie)
                dic["DNS"] = res_couche_app
                dic["DHCP"] = ""

        dic["Ethernet"] = resEthernet
        dic["IP"] = resIP
        dic["UDP"] = resUDP

        s=s+resEthernet+resIP+resUDP+res_couche_app
        
        liste_info.append(s)

    return liste_info
    