from securityheaders.models.cors import CORSDirective

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
