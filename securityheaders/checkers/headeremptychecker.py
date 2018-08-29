from securityheaders.checkers import SyntaxChecker, FindingType, Finding, FindingSeverity
from securityheaders.models import ModelFactory, SecurityHeader

class HeaderEmptyChecker(SyntaxChecker):

    def check(self, headers, opt_options=dict()):
        headernames = ModelFactory().getheadernames()

        findings = []
        for header in headernames:
            hdr = ModelFactory().getheader(header)

            try:
                obj = self.extractheader(headers, hdr)
                findings.extend(self.mycheck(obj))
            except:
                pass
        return findings

    def mycheck(self, data):
        if not data:
            return []
        if not data.hasdirectives() and isinstance(data, SecurityHeader):
            return [Finding(data.headerkey,FindingType.MISSING_HEADER,str(data.headerkey) + ' header is empty.', FindingSeverity.INFO, data.headerkey)]
        return []
