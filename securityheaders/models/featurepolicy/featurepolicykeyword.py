from securityheaders.models import Keyword

class FeaturePolicyKeyword(Keyword):
    SELF = "'self'"
    NONE = "'none'"
    STAR = "*"


    @staticmethod
    def isKeyword(keyword):
        """ Checks whether a given string is a FeaturePolicyKeyword.

        Args:
            keyword (str): the string to validate
        """
        return hasattr(FeaturePolicyKeyword, keyword)

    @staticmethod
    def isValue(keyword):
        return keyword in list(map(str, FeaturePolicyKeyword))
