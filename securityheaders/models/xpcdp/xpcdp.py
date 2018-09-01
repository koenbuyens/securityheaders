from securityheaders.models import SecurityHeader
from securityheaders.models.xpcdp import XPermittedCrossDomainPoliciesDirective
from securityheaders.models.annotations import *

@description('This header defines a cross-domain policy for clients such as Adobe Flash Player or Adobe Acrobat.')
@headername('x-permitted-cross-domain-policies')
@headerref('https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html')
class XPermittedCrossDomainPolicies(SecurityHeader):
    directive = XPermittedCrossDomainPoliciesDirective
    
    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, XPermittedCrossDomainPolicies.directive)
    
    def is_none(self):
        try:
            if self.parsedstring:
                return XPermittedCrossDomainPoliciesDirective.NONE in self.keys()
            return False
        except:
            pass
        return False

