from securityheaders.models.cors import CORSDirective

class AccessControlAllowOriginDirective(CORSDirective):
    STAR ='*'
    NULL = 'null'

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, AccessControlAllowOriginDirective):
            return True
        if directive.startswith('http:') or directive.startswith('https'):
            return True

        return any(directive.lower() == item.value.lower() for item in list(cls))
