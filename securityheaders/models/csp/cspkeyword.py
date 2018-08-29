from securityheaders.models import Keyword

class CSPKeyword(Keyword):
    SELF = "'self'"
    NONE = "'none'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    STAR = "*"


    @staticmethod
    def isKeyword(keyword):
        """ Checks whether a given string is a CSP keyword.

        Args:
            keyword (str): the string to validate
        """
        return hasattr(CSPKeyword, keyword)

    @staticmethod
    def isValue(keyword):
        return keyword in list(map(str, CSPKeyword))
