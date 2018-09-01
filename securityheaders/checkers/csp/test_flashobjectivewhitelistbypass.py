import unittest
from securityheaders.checkers import FindingSeverity
from securityheaders.checkers.csp import CSPFlashObjectWhitelistBypassChecker, CSPReportOnlyFlashObjectWhitelistBypassChecker

class FlashWhitelistBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPFlashObjectWhitelistBypassChecker()
       self.y = CSPReportOnlyFlashObjectWhitelistBypassChecker()

       self.options = dict()
       self.options['CSPFlashObjectWhitelistBypassChecker'] = dict()
       self.options['CSPFlashObjectWhitelistBypassChecker']['bypasses'] = ['//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf']
       self.options['CSPReportOnlyFlashObjectWhitelistBypassChecker'] = dict()
       self.options['CSPReportOnlyFlashObjectWhitelistBypassChecker']['bypasses'] = ['//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf']

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
       hasx4['content-security-policy'] = "default-src 'none'; object-src buyens.org"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #restrict to none if possible

    def test_KnownBypass(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; object-src ajax.googleapis.com"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_ValidCSPRO(self):
        hasx4 = dict()
        hasx4['content-security-policy-report-only'] = "default-src 'none'; object-src buyens.org"
        result = self.y.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #restrict to none if possible
    
    def test_KnownBypassRO(self):
        hasx5 = dict()
        hasx5['content-security-policy-report-only'] = "default-src 'none'; object-src ajax.googleapis.com"
        result = self.y.check(hasx5, self.options)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

if __name__ == '__main__':
    unittest.main()
