from securityheaders.checkers import Checker, FindingType, Finding, FindingSeverity
from securityheaders.models import ModelFactory

class HeaderMissingChecker(Checker):
    
    def check(self, headers, opt_options=dict()):
        findings = []
        headernames = ModelFactory().getheadernames()
        for header in headernames:
            hdr = ModelFactory().getheader(header)
            try:
                obj = self.extractheader(headers, hdr)
                if not obj:
                    obj = hdr("")
                    if hasattr(obj, 'required') and obj.required:
                        description = obj.description if hasattr(obj,'description') else ''
                        result = Finding(header, FindingType.MISSING_HEADER, str(obj.headerkey) + ' header not present. ' + str(description),FindingSeverity.INFO, None)
                        findings.append(result)
            except:
                pass
        return findings
