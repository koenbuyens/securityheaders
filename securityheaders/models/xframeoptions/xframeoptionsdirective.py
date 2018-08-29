from securityheaders.models import Directive

from securityheaders.models.annotations import requireddirectives, requireddirectivevalues

@requireddirectivevalues('allow-from')
class XFrameOptionsDirective(Directive):
    DENY = 'deny'
    SAMEORIGIN = 'sameorigin'
    ALLOW_FROM = 'allow-from'

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, XFrameOptionsDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)
