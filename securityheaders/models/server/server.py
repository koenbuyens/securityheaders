from securityheaders.models import Header
from securityheaders.models.annotations import description, headername, headerref

@description('Header describing the server software.')
@headername('server')
@headerref('https://tools.ietf.org/html/rfc7231#section-7.4.2')
class Server(Header):

    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
