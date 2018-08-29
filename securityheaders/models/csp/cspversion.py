from enum import Enum

class CSPVersion(Enum):
    CSP1 = 1
    CSP2 = 2
    CSP3 = 3

    def __lt__(self, other):
        """ Checks whether another CSPVersion is lower than this version

        Args:
            other (CSPVersion): the CSPVersion to compare with
        """
        return self.value < other.value

    def __eq__(self, other):
        """ Checks whether another CSPVersion is equal to this version

        Args:
            other (CSPVersion): the CSPVersion to compare with
        """
        return self.value == other.value

    def __ge__(self, other):
        """ Checks whether another CSPVersion is greater than this version

        Args:
            other (CSPVersion): the CSPVersion to compare with
        """
        return self.value > other.value

    def __str__(self):
        """ Returns a string representaiton of this CSP Version   
        """
        return str("CSP Version " + str(self.value))   
