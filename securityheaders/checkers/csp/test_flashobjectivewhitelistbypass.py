import unittest
from securityheaders.checkers import FindingSeverity
from securityheaders.checkers.csp import CSPFlashObjectWhitelistBypassChecker

class FlashWhitelistBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPFlashObjectWhitelistBypassChecker()
       self.options = dict()
       self.options['CSPFlashObjectWhitelistBypassChecker'] = dict()
       self.options['CSPFlashObjectWhitelistBypassChecker']['bypasses'] = ['//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf']

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

    def test_ValidCSP(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "default-src 'none'; object-src buyens.org"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #restrict to none if possible

    def test_KnownBypass(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; object-src ajax.googleapis.com"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.HIGH) #known bypass

if __name__ == '__main__':
    unittest.main()
