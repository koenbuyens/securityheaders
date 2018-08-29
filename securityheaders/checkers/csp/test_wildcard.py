
import unittest

from securityheaders.checkers.csp import CSPWildCardChecker

class WildCardTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPWildCardChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_wildCard(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src *'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_NoWildCard(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = 'script-src 200.200.200.200'
       self.assertEquals(self.x.check(hasx4), [])

    def test_NoWildCard2(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       self.assertEquals(self.x.check(hasx3), [])

    def test_NoWildCard3(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])

    def test_NoWildCard2(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "object-src *; script-src 'none';"
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_NoWildCardDefaultSrc(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "default-src *; script-src 'none';" #object-src inherits default-src and is thus insecure
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

if __name__ == '__main__':
    unittest.main()
