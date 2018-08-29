from securityheaders.models import Header
from securityheaders.models.annotations import *

@description('Header describing the server software.')
@headername('x-aspnetmvc-version')
@headerref('https://support.microsoft.com/en-us/help/4295294/update-rollup-13-for-windows-azure-pack')
class XAspnetMvcVersion(Header):

    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
