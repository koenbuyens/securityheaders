from securityheaders.models import Directive

class CORSDirective(Directive):


    @classmethod
    def directiveseperator(cls):
        return ','

    @classmethod
    def directivevalueseperator(cls):
        return ','


    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, CORSDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in list(cls))
