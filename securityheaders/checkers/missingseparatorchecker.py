from securityheaders.checkers import SyntaxChecker, FindingType, Finding, FindingSeverity
from securityheaders.models import ModelFactory

class MissingSeparatorChecker(SyntaxChecker):
    def check(self, headers, opt_options=dict()):
        findings = []
        headernames = ModelFactory().getheadernames()
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

        if not hasattr(data, 'directive'):
            return []
        isDirective = data.directive
        if not isDirective:
            return []

        directiveseperator = isDirective.directiveseperator()

        for directive in data.keys():
            for value in data[directive]:             
                value = str(value)
                if isDirective.isDirective(value):
                    finding = Finding(data.headerkey, FindingType.MISSING_SEMICOLON,'Did you forget the '+ str(directiveseperator) + ' character? "' + str(value) + '" seems to be a directive, not a value',FindingSeverity.SYNTAX, directive, value)
                    if not finding in findings:
                        findings.append(finding)
                for directive2 in list(isDirective):
                    if str(directive2) in str(value).lower()and not isDirective.isDirective(value) and not str(directive2) +'.' in str(value).lower() and not "_" + str(directive2) in str(value).lower(): #to avoid things like https://*.sandbox.paypal.com or xss_report                        
                        finding = Finding(data.headerkey, FindingType.MISSING_SEMICOLON,'Did you forget the '+ str(directiveseperator) + ' character? "' + str(value) + '" seems to be a directive, not a value',FindingSeverity.SYNTAX, directive, value)
                        if not finding in findings:
                            findings.append(finding)
           
        return findings 
