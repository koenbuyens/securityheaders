from securityheaders.models.cors import CORSDirective
from securityheaders.models.annotations import *

@anydirective
class AccessControlAllowHeadersDirective(CORSDirective):

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        return isinstance(directive, str)

    @classmethod
    def directiveseperator(cls):
        return ','
