from enum import Enum

class FindingSeverity(Enum):
    CRITICAL = 0 #Critical severity
    HIGH = 10 #high severity
    MEDIUM = 30 #medium severity
    LOW = 55 #low severity
    INFO = 60 #informational severity
    NONE = 100 #no severity
    SYNTAX = 20 #syntax error
    HIGH_MAYBE = 40 #high severity, but needs to be confirmed by user
    STRICT_CSP = 45 #the CSP does not adhere to strict guidelines
    MEDIUM_MAYBE = 50 #medium severity, but needs to be confired by user
    ERROR = 200

    def __str__(self):
        """ Returns a string representaiton of this finding severity   
        """
        return str(self.name.lower())  
