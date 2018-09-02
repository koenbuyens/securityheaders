from securityheaders.checkers import FindingSeverity, Finding, FindingType
from securityheaders.models import XFrameOptions, CSP

from securityheaders.checkers.xframeoptions import XFrameOptionsChecker
from securityheaders.checkers.csp import CSPChecker

class CSPXFrameOptionsInconsistentChecker(XFrameOptionsChecker, CSPChecker):
    def check(self, headers, opt_options=dict()):
        opts = self.getxframeoptions(headers)
        csp = self.getcsp(headers)
        if not opts or not csp:
            return []

        value = None
        if csp.directive.FRAME_ANCESTORS in csp.keys():
            value = csp[csp.directive.FRAME_ANCESTORS]
        if not value:
            return []

        inconsistent = False
        if opts.deny() and not self.__notcontains_keyword__(value, csp.keyword.NONE):
            inconsistent = True
        elif opts.sameorigin() and not self.__notcontains_keyword__(value, csp.keyword.SELF):
            inconsistent = True
        elif opts.allowfrom() not in value:
            inconsistent = True

        if inconsistent:
            return [Finding(CSP.headerkey, FindingType.INCONSISTENCIES, 'The X-Frame-Options and the Content-Security-Policy have different framing policies. The Content-Security-Policy header had a ' + str(csp.directive.FRAME_ANCESTORS) + ' directive with as value ' + ", ".join(value) + ', while the X-Frame-Options header had as value "' + str(opts.keys()[0]) + '". Browsers should follow the CSP, but that behavior is not guaranteed.' ,FindingSeverity.INFO, csp.directive.FRAME_ANCESTORS, value)]
        return []

    def __notcontains_keyword__(self, value, keyword):
         return keyword != value and keyword.value not in str(value)

