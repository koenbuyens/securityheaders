#checks whether unsafe-inline has been used.
# unsafe-inline for script-src (or for default-src when no script-src is provided) allows execution of inline third-party JavaScript.

from securityheaders.models.csp import CSPKeyword, CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPUnsafeInlineChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        if not headers:
            return []
        directive = CSP.directive.SCRIPT_SRC
        values = self.effectiveDirectiveValues(headers,directive, opt_options)
        # Check if unsafe-inline is present.
        if CSPKeyword.UNSAFE_INLINE in values or str(CSPKeyword.UNSAFE_INLINE) in values:
            return [Finding(CSP.headerkey, FindingType.SCRIPT_UNSAFE_INLINE, '\'' + CSPKeyword.UNSAFE_INLINE.value + '\' allows the execution of unsafe in-page scripts and event handlers.',FindingSeverity.HIGH, directive, CSPKeyword.UNSAFE_INLINE.value)]
        return []

