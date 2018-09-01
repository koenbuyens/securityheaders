from securityheaders.checkers import Finding, FindingSeverity, FindingType
from securityheaders.models import XContentTypeOptions
from .checker import XContentTypeOptionsChecker

class XContentTypeOptionsNoSniffChecker(XContentTypeOptionsChecker):
    def check(self, headers, opt_options=dict()):
        opts = self.getxcontenttypeoptions(headers)
        if not opts:
            return []
        if not opts.nosniff():
            directive = opts.directives()[0] if opts.directives() else None
            return [Finding(XFrameOptions.headerkey, FindingType.NOSNIFF, 'This header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff"' ,FindingSeverity.MEDIUM, directive, None)]
        return []
