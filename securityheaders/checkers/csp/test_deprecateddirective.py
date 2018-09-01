import unittest

from securityheaders.checkers.csp import CSPDeprecatedDirectiveChecker, CSPReportOnlyDeprecatedDirectiveChecker

class DeprectedDirectiveTest(unittest.TestCase):
    def setUp(self):
        self.x = CSPDeprecatedDirectiveChecker()
        self.y = CSPReportOnlyDeprecatedDirectiveChecker()


    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_NonePolicy(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_DeprecatedReportUriCSP3(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
    
    def test_RODeprecatedReportUriCSP3(self):
        hasx3 = dict()
        hasx3['content-security-policy-report-only'] = "report-uri http://foo.bar/csp"
        result = self.y.check(hasx3)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_ValidCSP(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
       self.assertEqual(self.x.check(hasx2), [])

    def test_ROValidCSP(self):
        hasx2 = dict()
        hasx2['content-security-policy-report-only'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
        self.assertEqual(self.y.check(hasx2), [])

if __name__ == '__main__':
    unittest.main()
