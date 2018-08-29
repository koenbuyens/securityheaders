from securityheaders.models import Directive

class XContentTypeOptionsDirective(Directive):
    NOSNIFF = 'nosniff'


    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, XContentTypeOptionsDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)
