from securityheaders.models.setcookie import SetCookie
from securityheaders.checkers import Checker

class SetCookieChecker(Checker):
    def __init__(self):
        pass

    def getcookie(self, headers):
         return self.extractheader(headers, SetCookie)
