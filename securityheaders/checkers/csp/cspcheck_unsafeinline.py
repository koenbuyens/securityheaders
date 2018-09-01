from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckUnsafeInline(CSPCheck):
    
    def __init__(self, csp, directive, effectiveDirectiveValues):
        self.csp = csp
        self.directive = directive
        self.values = effectiveDirectiveValues

    def check(self):
        csp = self.csp
        if not csp or not csp.parsedstring:
            return []
    
    
        # Check if unsafe-inline is present.
        if csp.keyword.UNSAFE_INLINE in self.values or str(csp.keyword.UNSAFE_INLINE) in self.values:
            return [Finding(csp.headerkey, FindingType.SCRIPT_UNSAFE_INLINE, '\'' + csp.keyword.UNSAFE_INLINE.value + '\' allows the execution of unsafe in-page scripts and event handlers.',FindingSeverity.HIGH, self.directive, csp.keyword.UNSAFE_INLINE.value)]
        return []
