from securityheaders.models import Header
from securityheaders.models.annotations import description, headername

@description('Header describing the server software.')
@headername('server')
class Server(Header):

    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
