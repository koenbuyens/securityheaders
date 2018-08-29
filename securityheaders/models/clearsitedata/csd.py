from securityheaders.models import SecurityHeader
from securityheaders.models.clearsitedata import ClearSiteDataDirective
from securityheaders.models.annotations import description, headername

@description('Clearing browser data for origin.')
@headername('clear-site-data')
class ClearSiteData(SecurityHeader):
    directive = ClearSiteDataDirective
    
    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, ClearSiteData.directive)
    
    def methods(self):
        if self.parsedstring:
            return self.parsedstring.keys()
        return []

