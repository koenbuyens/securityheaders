from securityheaders.models import Directive
from securityheaders.models.annotations import requireddirectives, requireddirectivevalues

@requireddirectives('max-age')
@requireddirectivevalues('max-age')
class HSTSDirective(Directive):
    INCLUDESUBDOMAINS = 'includesubdomains'
    MAX_AGE = 'max-age'
    PRELOAD = 'preload'

    @classmethod
    def valueseperator(cls):
        return '='

    @classmethod
    def directivevalueseperator(cls):
        return '='

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, HSTSDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)
