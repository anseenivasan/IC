class Card:
    # Initializer (constructor)
    def __init__(self,face,suit,value,points):
        self.face = face
        self.suit = suit
        self.value = value
        self.points = points

    # Method
    def getCardName(self): # eg : three of spades
        return self.face + " of " + self.suit

    def setStatus(self,newstatus): # change status  (deck,hand1,hand2)
        self.status = newstatus


