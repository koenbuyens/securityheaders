import unittest

from securityheaders.checkers import FindingSeverity
from securityheaders.checkers.csp import CSPScriptWhitelistBypassChecker,CSPReportOnlyScriptWhitelistBypassChecker

class CSPScriptWhitelistBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPScriptWhitelistBypassChecker()
       self.y = CSPReportOnlyScriptWhitelistBypassChecker()
       self.options = dict()
       self.options['CSPScriptWhitelistBypassChecker'] = dict()
       self.options['CSPScriptWhitelistBypassChecker']['angular'] = ['https://gstatic.com/fsn/angular_js-bundle1.js']
       self.options['CSPReportOnlyScriptWhitelistBypassChecker'] = dict()
       self.options['CSPReportOnlyScriptWhitelistBypassChecker']['angular'] = ['https://gstatic.com/fsn/angular_js-bundle1.js']

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_ValidCSP(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "default-src 'none'; script-src buyens.org"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #validate if the url does not have known bypasses

    def test_KnownBypass(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src https://gstatic.com/fsn/angular_js-bundle1.js"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_KnownSelf(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src 'self'"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.MEDIUM_MAYBE)

    def test_ValidCSPRO(self):
       hasx4 = dict()
       hasx4['content-security-policy-report-only'] = "default-src 'none'; script-src buyens.org"
       result = self.y.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #validate if the url does not have known bypasses
    
    def test_KnownBypassRO(self):
        hasx5 = dict()
        hasx5['content-security-policy-report-only'] = "default-src 'none'; script-src https://gstatic.com/fsn/angular_js-bundle1.js"
        result = self.y.check(hasx5, self.options)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass
    
    def test_KnownSelfRO(self):
        hasx5 = dict()
        hasx5['content-security-policy-report-only'] = "default-src 'none'; script-src 'self'"
        result = self.y.check(hasx5)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, FindingSeverity.MEDIUM_MAYBE)

if __name__ == '__main__':
    unittest.main()
