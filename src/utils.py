import copy

def hex_to_dec(hex):
    return int(hex,16)

def dec_to_hex(dec):
    return hex(dec).split('x')[-1]

def getOffset(ligne):
    temp = ligne.split(' ')
    return temp[0]

def offset_valide(hex):
    hex = hex.rstrip('\n')
    liste = ['1', '2', '3', '4' ,'5' ,'6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f']
    if len(hex) < 2:
        return False
    for i in range(len(hex)):
        if hex[i].lower() not in liste:
            return False
    return True

def octet_valide(hex):
    hex = hex.rstrip('\n')
    liste = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f']
    if len(hex) != 2:
        return False
    for i in range(len(hex)):
        if hex[i].lower() not in liste:
            return False
    return True

def ligne_valide_simple(ligne):
    if ligne[0] == " ":
        return False
    ligne_temp = copy.deepcopy(ligne)
    temp = ligne.split()
    if not offset_valide(temp[0]):
        return False
    ligne_temp = ligne_temp.split(' ')[1:] #enlever offset et 1 espace
    if len(ligne_temp) == 0:
        return False
    return octet_valide(ligne_temp[0])

def hex_to_binaire(hex, nbBits):
    b = bin(hex_to_dec(hex))[2:]
    if len(b) == nbBits:
        return b
    if len(b) > nbBits:
        raise Exception("Impossible de transformer en {} bits".format(nbBits))
    i = 0
    for i in range(nbBits-len(b)):
        b = "0"+b
    return b

def sec_to_hms(sec):
    """
    Seconds -> Hour - minutes - seconds
    :param sec: nombre de secondes
    :return: H-M-S
    """
    h = sec//3600
    m = (sec%3600)//60
    s = sec - h*3600 - m*60
    string = str(h)+" hour(s), "+str(m)+" minute(s), "+str(s)+" second(s)"
    return string

def test_coherence_offset(trame, file_base):
    """
    :param trame: une liste des lignes d'une trame, ses offsets sont CONFORMES
    :param file_base: Pour trouver la position des lignes incomplètes dans le fichier origine
    :return: (True, nombre d'octets par ligne) s'il existe une cohérence entre des offset, (False, pos(deb, fin)) sinon.
    """
    liste_offset = [hex_to_dec(getOffset(x)) for x in trame] # liste des offsets en decimal
    liste_difference = [liste_offset[x] - liste_offset[x-1] for x in range(1, len(liste_offset))] #liste des différence entre deux offsets
    if len(list(set(liste_difference))) != 1: #Si les différences ne sont pas cohérentes
        pos = []
        for i in range(len(file_base)):
            if trame[0] == file_base[i] or trame[-1] == file_base[i]:
                pos.append(i+1)
            if len(pos) == 2:
                break
        return False, pos
    return True, [liste_difference[0]]

def divise_en_trames(lignes):
    """
    Transformer un ensemble des lignes du fichiers en sous-ensembles des lignes
    :param lignes: les lignes du fichier dont offsets sont CONFORMES
    :return: liste des trames non traitées
    """
    liste_trames = []
    liste_temp = []
    i = 0
    while i < len(lignes):
        temp = copy.deepcopy(lignes[i])  # car getOffset modifiera la ligne en coupant les espaces
        if hex_to_dec(getOffset(temp)) == 0: #debut d'une trame
            liste_trames.append(liste_temp) #ajouter la trame precédente à la liste des trames
            liste_temp = [lignes[i]] #Réinitialiser la liste temp avec 1ère ligne de la trame courante
        else:
            liste_temp.append(lignes[i])
        if i == len(lignes)-1: #Nous arrivons à la fin
            liste_trames.append(liste_temp)
        i += 1
    return liste_trames[1:] #Enlever 1er élément - une liste vide


def trame_en_liste_octet(trame, nboctet_par_ligne, file_base):
    """
    Transformer une trame dont norme a été validée non traitée en une liste d'octets
    :param trame: une trame en texte
    :param nboctet_par_ligne: Nombre d'octet par ligne
    :param file_base: Pour trouver la position des lignes incomplètes dans le fichier origine
    :return: liste des octets dans la trame
    """
    liste_octet = []
    liste_incomplete = []
    for ligne in trame:
        if ligne != trame[-1]: #Nous traitons la dernière ligne différemment
            temp = ligne.split(' ')[1:nboctet_par_ligne+1] #enlever offset puis prendre nbOctet
            if not all(map(octet_valide, temp)): #s'il existe un octet non conforme -> ligne incomplète
                for i in range(0, len(file_base)): #Trouver la position origine de la ligne
                    if file_base[i] == ligne:
                        liste_incomplete.append(i+1)
                        break
            for x in temp:  #Ajouter les octets dans la liste d'octets
                liste_octet.append(x)
        else: #La dernière ligne
            temp = ligne.split(' ')[1:] #couper 1 espace entre les mots et enlever l'offset
            for i in temp:
                if i == '': # >=2 espaces à la suite, c-t-d les éléments suivants sont des valeurs textuelles
                    break
                if octet_valide(i):
                    liste_octet.append(i)
    return liste_octet, liste_incomplete






















