from securityheaders.models import SecurityHeader
from securityheaders.models.expectct import ExpectCTDirective
from securityheaders.models.annotations import requiredheader, description, headername

@requiredheader
@description('Expect-CT allows a site to determine if they are ready to enforce their CT policy.')
@headername('expect-ct')
class ExpectCT(SecurityHeader):
    directive = ExpectCTDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, ExpectCTDirective)

    def enforce(self):
        try:
            result = ExpectCTDirective.ENFORCE in self.parsedstring
            return result
        except:
            return False

    def reporturi(self):
        try:
            return self.parsedstring[ExpectCTDirective.REPORT_URI][0]
        except IndexError:
            return "" #there is a key, but it is empty
        except KeyError:
            return None #there is no key

    def maxage(self):
        try:
            return int(self.parsedstring[ExpectCTDirective.MAX_AGE][0])
        except Exception, e:
            return None
