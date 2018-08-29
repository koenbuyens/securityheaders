from securityheaders.models import Directive

class ClearSiteDataDirective(Directive):
    CACHE = 'cache','"cache"'
    COOKIES = 'cookies','"cookies"'
    STORAGE = 'storage','"storage"'
    EXECUTIONCONTEXTS = 'executioncontexts','"executioncontexts"'
    STAR = '*','"*"'
    
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
        if isinstance(directive, ClearSiteDataDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)

