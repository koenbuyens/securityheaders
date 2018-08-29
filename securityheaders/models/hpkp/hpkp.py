from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import description, headername

@description('TODO')
@headername('public-key-pins')
class PublicKeyPins(SecurityHeader):
    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
