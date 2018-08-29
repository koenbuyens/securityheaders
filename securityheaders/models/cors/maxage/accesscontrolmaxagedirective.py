from securityheaders.models.cors import CORSDirective

class AccessControlMaxAgeDirective(CORSDirective):
    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        try:
            int(directive)
            return True
        except:
            return False
