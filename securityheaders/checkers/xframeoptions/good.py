from securityheaders.checkers import FindingSeverity, Finding, FindingType
from securityheaders.models import XFrameOptions

from .checker import XFrameOptionsChecker

class XFrameOptionsNotAllowFromChecker(XFrameOptionsChecker):
    def check(self, headers, opt_options=dict()):
        opts = self.getxframeoptions(headers)
        if not opts:
            return []
        if opts.allowfrom():
            directive = opts.directives()[0] if opts.directives() else None
            return [Finding(XFrameOptions.headerkey, FindingType.ALLOW_FROM, 'This header tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. The recommended value is "x-frame-options: SAMEORIGIN."' ,FindingSeverity.MEDIUM_MAYBE, directive, None)]
        return []

