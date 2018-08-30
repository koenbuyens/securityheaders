from securityheaders.checkers import SyntaxChecker, FindingType, Finding, FindingSeverity
from securityheaders.models import ModelFactory

class MissingDirectiveChecker(SyntaxChecker):
    
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

        if not hasattr(directive, 'requireddirectives'):
            return []
        if not directive.requireddirectives:
            return []
        result = []
        for required in directive.requireddirectives:
            required = directive(required)
            allkeys = [str(key) for key in data.keys()]
            if not required in data.keys():
                result.append(Finding(data.headerkey, FindingType.MISSING_DIRECTIVES,str(required) + ' directive is missing.',FindingSeverity.SYNTAX,required,",".join(allkeys)))
        return result
