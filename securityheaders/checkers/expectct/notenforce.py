from checker import ExpectCTChecker
from securityheaders.models import ExpectCT
from securityheaders.checkers import Finding, FindingType, FindingSeverity

class ExpectCTNotEnforcedChecker(ExpectCTChecker):
    
    def check(self, headers, opt_options=dict()):
        findings = []
        expectct = self.getexpectct(headers)
        
        if not expectct:
            return findings
        
        findings = []
        if not expectct.enforce():
            findings.append(Finding(expectct.headerkey,FindingType.NOT_ENFORCED,expectct.headerkey + 'is not enforced as ' + ExpectCT.directive.ENFORCE.value  + ' is not set.', FindingSeverity.LOW, None))
        if expectct.maxage() == 0:
            findings.append(Finding(expectct.headerkey,FindingType.NOT_ENFORCED,expectct.headerkey + 'is not enforced as ' + ExpectCT.directive.MAX_AGE.value  + ' is set to 0', FindingSeverity.LOW, '0'))
        elif expectct.maxage() < 3000:
            findings.append(Finding(expectct.headerkey,FindingType.NOT_ENFORCED,expectct.headerkey + 'is only enforced for a very short amount of time as ' + ExpectCT.directive.MAX_AGE.value  + ' is set to ' + str(expectct.maxage()), FindingSeverity.LOW, str(expectct.maxage())))
        return findings
