
import unittest

from securityheaders.checkers.csp import CSPSCRHTTPChecker

class HTTPTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPSCRHTTPChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_NoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_HTTPURI(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_HTTPSURI(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "report-uri https://foo.bar/csp"
       self.assertEquals(self.x.check(hasx4), [])

    def test_NoURI(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
       self.assertEquals(self.x.check(hasx2), [])

if __name__ == '__main__':
    unittest.main()