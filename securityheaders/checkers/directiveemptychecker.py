from securityheaders.checkers import SyntaxChecker, FindingType, Finding, FindingSeverity
from securityheaders.models import ModelFactory

class EmptyDirectiveChecker(SyntaxChecker):
    
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
        if not hasattr(data, 'directive'):
            return []
        directive = data.directive

        if not hasattr(directive, 'requireddirectivevalues'):
            return []
        if not directive.requireddirectivevalues:
            return []
        result = []
        for required in directive.requireddirectivevalues:
            required = directive(required)
            if required in data.keys():
                value = data[required]
                if not value:
                    result.append(Finding(data.headerkey, FindingType.MISSING_VALUES,str(required) + ' is defined, but does not have a value.',FindingSeverity.SYNTAX,required, None))
        return result
