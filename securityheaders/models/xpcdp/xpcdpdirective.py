from securityheaders.models import Directive

class XPermittedCrossDomainPoliciesDirective(Directive):
    NONE = 'none'
    MASTER_ONLY = 'master-only'
    BY_CONTENT_TYPE = 'by-content-type'
    BY_FTP_FILENAME = 'by-ftp-filename'
    ALL = 'all'
    
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
        if isinstance(directive, XPermittedCrossDomainPoliciesDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)

