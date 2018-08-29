from securityheaders.models import Header
from securityheaders.models.annotations import *

@description('Header describing the server software.')
@headername('x-powered-by')
@headerref('https://stackoverflow.com/questions/1288338/why-does-asp-net-framework-add-the-x-powered-byasp-net-http-header-in-respons')
class XPoweredBy(Header):
    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
