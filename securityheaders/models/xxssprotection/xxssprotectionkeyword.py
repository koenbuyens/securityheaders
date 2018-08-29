from securityheaders.models import Keyword

class XXSSProtectionKeyword(Keyword):
    BLOCK = "block"

    @staticmethod
    def isKeyword(keyword):
        """ Checks whether a given string is a XSSProtection keyword.

        Args:
            keyword (str): the string to validate
        """
        return hasattr(XSSProtectionKeyword, keyword)
