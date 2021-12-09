class LigneException(BaseException):
    def __init__(self, liste):
        message = "Lignes incomplètes : "
        for i in liste:
            if i == liste[-1]:
                message += str(i)
            else:
                message += str(i)+", "
        super().__init__(message)

class TrameException(BaseException):
    def __init__(self, liste):
        message = "Offsets incohérents : "
        for i in range(len(liste)):
            if i == len(liste)-1:
                message += "lignes "+str(liste[i][0])+" à "+str(liste[i][1])
            else:
                message += "lignes "+str(liste[i][0])+" à "+str(liste[i][1])+", "
        super().__init__(message)
