from securityheaders.models import Directive
from securityheaders.models.annotations import *

@requireddirectivevalues('expires','max-age','domain','path','samesite')
@anydirective #anything can be a directive (i.e. the cookie name)
class SetCookieDirective(Directive):
    EXPIRES='expires'
    MAX_AGE = 'max-age'
    DOMAIN='domain'
    PATH='path'
    SECURE='secure'
    HTTPONLY='httponly'
    SAMESITE ='samesite'
    
    @classmethod
    def directiveseperator(cls):
        return ';'
    
    @classmethod
    def directivevalueseperator(cls):
        return '='

    @classmethod
    def valueseperator(cls):
        return '='
    
    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive
            
            Args:
            directive (str): the string to validate
            """
        if isinstance(directive, SetCookieDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)

