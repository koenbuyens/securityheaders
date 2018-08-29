from securityheaders.models import Directive
from securityheaders.models.annotations import requireddirectives

@requireddirectives('noopen')
class XDownloadOptionsDirective(Directive):
    NOOPEN = 'noopen'
    
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
        if isinstance(directive, XDownloadOptionsDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)

