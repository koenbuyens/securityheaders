from securityheaders.models.xpcdp import XPermittedCrossDomainPolicies
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders.checkers.xpcdp import XPermittedCrossDomainPolicyChecker

class XPCDPNotNoneChecker(XPermittedCrossDomainPolicyChecker):
    def check(self, headers, opt_options=dict()): 
        xpcdp = self.getxpcdp(headers)

        if not xpcdp:
            return []
        
        if not xpcdp.is_none():
            directives = [str(x) for x in xpcdp.keys()]
            return [Finding(XPermittedCrossDomainPolicies.headerkey, FindingType.INSECURE_HEADER, 'The policy is not set to none. Make sure that you do not use flash.', FindingSeverity.MEDIUM_MAYBE, XPermittedCrossDomainPolicies.directive.NONE, ",".join(directives))]
        return []
