from enum import Enum

class Keyword(Enum):

    def __str__(self):
        """ Returns a string representaiton of this CSP keyword   
        """
        return str(self.value.lower())   

    def lower(self):
        return str(self).lower()

    def startswith(self, value):
        return str(self).startswith(value)

    def find(self, value):
        return str(self).find(value)
