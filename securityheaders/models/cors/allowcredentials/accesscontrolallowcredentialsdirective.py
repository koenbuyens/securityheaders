from securityheaders.models.cors import CORSDirective
from securityheaders.models.annotations import requireddirectives

@requireddirectives('true')
class AccessControlAllowCredentialsDirective(CORSDirective):
    TRUE= 'true'

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, AccessControlAllowCredentialsDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in list(cls))
