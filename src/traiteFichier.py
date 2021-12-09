
def ouvrirFichier(path):
    return open(path, "rb")

def afficher(fichier):
    print(fichier.read())
    fichier.seek(0)

def rewind(fichier):
    fichier.seek(0)
