from securityheaders.checkers import InfoCollector, FindingType, Finding, FindingSeverity
from securityheaders.models import ModelFactory

class InfoDirectiveCollector(InfoCollector):

    def check(self, headers, opt_options=dict()):
        headernames = ModelFactory().getheadernames()
        findings = []
        for header in headernames:
            hdr = ModelFactory().getheader(header)
            try:
                obj = self.extractheader(headers, hdr)
                if obj and obj.parsedstring:
                    findings.extend(self.mycheck(obj))
            except:
                pass
        return findings

    def mycheck(self, data):
        findings = []

        if not data:
            return findings

        for mydirective in data.keys():
            if data.directive.isDirective(mydirective):
                value = data[mydirective]
                if value:
                    valstr = ''
                    for val in value:
                        valstr = valstr +  ' ' + str(val)
                else:
                    valstr = ""
                findings.append(Finding(data.headerkey, FindingType.INFO_DIRECTIVE,valstr,FindingSeverity.NONE,mydirective))
        return findings
