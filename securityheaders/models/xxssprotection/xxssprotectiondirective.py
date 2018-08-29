from securityheaders.models import Directive
from securityheaders.models.annotations import requireddirectives, requireddirectivevalues

@requireddirectivevalues('mode','report')
class XXSSProtectionDirective(Directive):

    ONE = '1'
    ZERO = '0'
    REPORT = 'report'
    MODE = 'mode'

    @classmethod
    def valueseperator(cls):
        return '='

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, XXSSProtectionDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)
