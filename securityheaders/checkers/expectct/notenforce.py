from securityheaders.models import ExpectCT
from securityheaders.checkers import Finding, FindingType, FindingSeverity

from .checker import ExpectCTChecker

class ExpectCTNotEnforcedChecker(ExpectCTChecker):
    
    def check(self, headers, opt_options=dict()):
        findings = []
        expectct = self.getexpectct(headers)
        
        if not expectct:
            return findings
        
        findings = []
        if not expectct.enforce():
            findings.append(Finding(expectct.headerkey,FindingType.NOT_ENFORCED,expectct.headerkey + 'is not enforced as ' + ExpectCT.directive.ENFORCE.value  + ' is not set.', FindingSeverity.LOW, ExpectCT.directive.ENFORCE,None))
        if expectct.maxage() == 0:
            findings.append(Finding(expectct.headerkey,FindingType.NOT_ENFORCED,expectct.headerkey + 'is not enforced as ' + ExpectCT.directive.MAX_AGE.value  + ' is set to 0', FindingSeverity.LOW, ExpectCT.directive.MAX_AGE,'0'))
        elif expectct.maxage() and expectct.maxage() < 3000:
            findings.append(Finding(expectct.headerkey,FindingType.NOT_ENFORCED,expectct.headerkey + 'is only enforced for a very short amount of time as ' + ExpectCT.directive.MAX_AGE.value  + ' is set to ' + str(expectct.maxage()), FindingSeverity.LOW, ExpectCT.directive.MAX_AGE,str(expectct.maxage())))
        return findings
