from securityheaders.models import SecurityHeader
from securityheaders.models.xdownloadoptions import XDownloadOptionsDirective
from securityheaders.models.annotations import *

@description('Prevent file downloads opening.')
@headername('x-download-options')
@headerref('https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/jj542450(v=vs.85)')
class XDownloadOptions(SecurityHeader):
    directive = XDownloadOptionsDirective
    
    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, XDownloadOptions.directive)
    
    def noopen(self):
        if self.parsedstring:
            return XDownloadOptionsDirective.NOOPEN in self.keys()
        return []

