from securityheaders.models import SecurityHeader
from securityheaders.models.xdownloadoptions import XDownloadOptionsDirective
from securityheaders.models.annotations import description, headername

@description('Prevent file downloads opening.')
@headername('x-download-options')
class XDownloadOptions(SecurityHeader):
    directive = XDownloadOptionsDirective
    
    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, XDownloadOptions.directive)
    
    def noopen(self):
        if self.parsedstring:
            return XDownloadOptionsDirective.NOOPEN in self.parsedstring.keys()
        return []

