from securityheaders.models import Header
from securityheaders.models.setcookie import SetCookieDirective
from securityheaders.models.annotations import *

@description('The Set-Cookie header is used to send cookies from the server to the user agent.')
@headername('set-cookie')
@headerref('https://tools.ietf.org/html/rfc6265#section-4.1')
class SetCookie(Header):
    directive = SetCookieDirective
    
    def __init__(self, unparsedstring):
        Header.__init__(self, unparsedstring, SetCookie.directive)

    def expires(self):
        try:
            return self.parsedstring[SetCookieDirective.EXPIRES][0]
        except IndexError:
            return "" #there is a key, but it is empty
        except KeyError:
            return None #there is no key

    def maxage(self):
        try:
            return int(self.parsedstring[SetCookieDirective.MAX_AGE][0])
        except Exception:
            return None

    def domain(self):
        try:
            return self.parsedstring[SetCookieDirective.DOMAIN][0]
        except IndexError:
            return "" #there is a key, but it is empty
        except KeyError:
            return None #there is no key

    def path(self):
        try:
            return self.parsedstring[SetCookieDirective.PATH][0]
        except IndexError:
            return "" #there is a key, but it is empty
        except KeyError:
            return None #there is no key

    def secure(self):
        try:
            result = SetCookieDirective.SECURE in self.parsedstring
            return result
        except:
            return False

    def httponly(self):
        try:
            result = SetCookieDirective.HTTPONLY in self.parsedstring
            return result
        except:
            return False

    def samesite(self):
        try:
            return self.parsedstring[SetCookieDirective.SAMESITE][0]
        except IndexError:
            return "" #there is a key, but it is empty
        except KeyError:
            return None #there is no key


    def geturls(self, directives):
        result = []
        for directive in directives:
            try:
                dirobj = SetCookieDirective(directive)
                if dirobj == SetCookieDirective.DOMAIN:
                    domain = self.domain() if self.domain else ''
                    path = self.path() if self.path else ''
                    url = domain + path
                    if url:
                        result.append(url)
            except:
                 pass
        return result
 

    def name(self):
        for key in self.keys():
            if not SetCookieDirective.isDirective(key):
                return key
        return None

    def value(self):
        try:
            return self.parsedstring[self.name()][0]
        except IndexError:
            return "" #there is a key, but it is empty
        except KeyError:
            return None #there is no key
