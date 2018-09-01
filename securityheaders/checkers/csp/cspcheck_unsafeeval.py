from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckUnsafeEval(CSPCheck):
    
    def __init__(self, csp, directive, effectiveDirectiveValues):
        self.csp = csp
        self.directive = directive
        self.values = effectiveDirectiveValues

    def check(self):
        csp = self.csp
        if not csp or not csp.parsedstring:
            return []

        # Check if unsafe-eval is present.
        if csp.keyword.UNSAFE_EVAL in self.values or str(csp.keyword.UNSAFE_EVAL) in self.values:
            return [Finding(csp.headerkey, FindingType.SCRIPT_UNSAFE_EVAL, csp.keyword.UNSAFE_EVAL.value + ' allows the execution of code injected into DOM APIs such as eval().',FindingSeverity.MEDIUM_MAYBE, self.directive, csp.keyword.UNSAFE_EVAL.value)]
        return []
