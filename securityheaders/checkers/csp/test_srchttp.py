
import unittest

from securityheaders.checkers.csp import CSPSCRHTTPChecker, CSPReportOnlySCRHTTPChecker

class HTTPTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPSCRHTTPChecker()
       self.y = CSPReportOnlySCRHTTPChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_NoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_HTTPURI(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_HTTPSURI(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "report-uri https://foo.bar/csp"
       self.assertEqual(self.x.check(hasx4), [])
    
    def test_HTTPURIRO(self):
        hasx3 = dict()
        hasx3['content-security-policy-report-only'] = "report-uri http://foo.bar/csp"
        result = self.y.check(hasx3)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
    
    def test_HTTPSURIRO(self):
        hasx4 = dict()
        hasx4['content-security-policy-report-only'] = "report-uri https://foo.bar/csp"
        self.assertEqual(self.y.check(hasx4), [])

    def test_NoURI(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
       self.assertEqual(self.x.check(hasx2), [])

if __name__ == '__main__':
    unittest.main()
