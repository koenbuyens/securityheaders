import unittest

from securityheaders.checkers import FindingSeverity
from securityheaders.checkers.csp import CSPScriptWhitelistBypassChecker

class CSPScriptWhitelistBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPScriptWhitelistBypassChecker()
       self.options = dict()
       self.options['CSPScriptWhitelistBypassChecker'] = dict()
       self.options['CSPScriptWhitelistBypassChecker']['angular'] = ['https://gstatic.com/fsn/angular_js-bundle1.js']

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
       hasx4['content-security-policy'] = "default-src 'none'; script-src buyens.org"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #validate if the url does not have known bypasses

    def test_KnownBypass(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src https://gstatic.com/fsn/angular_js-bundle1.js"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_KnownSelf(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src 'self'"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.MEDIUM_MAYBE)

if __name__ == '__main__':
    unittest.main()
