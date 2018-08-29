from securityheaders.checkers import InfoDisclosureChecker
from securityheaders.models import Server

class ServerPresentChecker(InfoDisclosureChecker):
    def check(self, headers, opt_options=dict()):
        return InfoDisclosureChecker.mycheck(self, Server.headerkey,headers,opt_options)         


