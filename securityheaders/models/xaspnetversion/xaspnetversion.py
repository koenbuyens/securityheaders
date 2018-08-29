from securityheaders.models import Header
from securityheaders.models.annotations import *

@description('Header describing the server software.')
@headername('x-aspnet-version')
@headerref('https://msdn.microsoft.com/en-us/library/cc224063.aspx')
class XAspnetVersion(Header):
    directive = None
    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
