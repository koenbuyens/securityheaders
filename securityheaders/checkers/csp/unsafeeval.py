
#checks whether unsafe-eval has been used

from securityheaders.models.csp import CSPKeyword, CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPUnsafeEvalChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        if not headers:
            return []
        directive = CSP.directive.SCRIPT_SRC
        values = self.effectiveDirectiveValues(headers,directive, opt_options)
        # Check if unsafe-eval is present.
        if CSPKeyword.UNSAFE_EVAL in values or str(CSPKeyword.UNSAFE_EVAL) in values:
            return [Finding(CSP.headerkey, FindingType.SCRIPT_UNSAFE_EVAL, '\'' + CSPKeyword.UNSAFE_EVAL.value + '\' allows the execution of code injected into DOM APIs such as eval().',FindingSeverity.MEDIUM_MAYBE, directive, CSPKeyword.UNSAFE_EVAL.value)]
        return []

