from enum import Enum

class FindingSeverity(Enum):
    ERROR = 2000
    CRITICAL = 1000 #Critical severity
    HIGH = 900 #high severity
    SYNTAX = 800 #syntax error
    HIGH_MAYBE = 750 #high severity, but needs to be confirmed by user
    MEDIUM = 700 #medium severity
    MEDIUM_MAYBE = 650 #medium severity, but needs to be confired by user
    STRICT_CSP = 600 #the CSP does not adhere to strict guidelines
    LOW = 500 #low severity
    INFO = 400 #informational severity
    NONE = 100 #no severity



    def __str__(self):
        """ Returns a string representaiton of this finding severity   
        """
        return str(self.name)  

    def __repr__(self):
        return self.__str__()

