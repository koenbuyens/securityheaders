from securityheaders.checkers import InfoDisclosureChecker
from securityheaders.models import XPoweredBy

class XPoweredByPresentChecker(InfoDisclosureChecker):
    def check(self, headers, opt_options=dict()):
        return InfoDisclosureChecker.mycheck(self, XPoweredBy.headerkey,headers, opt_options)         

