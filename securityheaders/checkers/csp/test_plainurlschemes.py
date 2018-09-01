import unittest

from securityheaders.checkers.csp import CSPPlainUrlSchemesChecker, CSPReportOnlyPlainUrlSchemesChecker


class UnsafeUrkSchemeTest(unittest.TestCase):

    def setUp(self):
        self.x = CSPPlainUrlSchemesChecker()
        self.y = CSPReportOnlyPlainUrlSchemesChecker()


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


    def test_All(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "script-src https: http: data:"
       self.assertIsNotNone(self.x.check(hasx4))
       self.assertEqual(len(self.x.check(hasx4)), 3) #all 3 of them

    def test_http(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "script-src http:"
       self.assertIsNotNone(self.x.check(hasx3))
       self.assertEqual(len(self.x.check(hasx3)), 1) #http:

    def test_validCSP(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEqual(self.x.check(hasx2), [])

    def test_httpro(self):
        hasx3 = dict()
        hasx3['content-security-policy-report-only'] = "script-src http:"
        self.assertIsNotNone(self.y.check(hasx3))
        self.assertEqual(len(self.y.check(hasx3)), 1) #http:
    
    def test_validCSPro(self):
        hasx2 = dict()
        hasx2['content-security-policy-report-only'] = "default-src 'self'; script-src tweakers.net"
        self.assertEqual(self.y.check(hasx2), [])

if __name__ == '__main__':
    unittest.main()
