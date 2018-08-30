from securityheaders.checkers import HeaderPresentChecker

class InfoDisclosureChecker(HeaderPresentChecker):
    def mycheck(self, header, headers, opt_options=dict()):
        return HeaderPresentChecker.mycheck(self, headers, header, 'This header gives an attacker info for more targeted attacks.', opt_options)
