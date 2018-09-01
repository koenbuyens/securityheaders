import unittest

from securityheaders.checkers.csp import CSPNonceLengthChecker, CSPReportOnlyNonceLengthChecker

class NonceLengthTest(unittest.TestCase):

    def setUp(self):
        self.x = CSPNonceLengthChecker()
        self.y = CSPReportOnlyNonceLengthChecker()

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

    def test_ShortNonce(self):
        hasx3 = dict()
        hasx3['content-security-policy'] = "script-src 'nonce-short'"
        result = self.x.check(hasx3)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_ShortNonce2(self):
        hasx4 = dict()
        hasx4['content-security-policy'] = "default-src 'self'; script-src 'nonce-'"
        result = self.x.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
    
    def test_ShortNonce2RO(self):
        hasx4 = dict()
        hasx4['content-security-policy-report-only'] = "default-src 'self'; script-src 'nonce-'"
        result = self.y.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_ValidNonce(self):
        hasx2 = dict()
        hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
        self.assertEqual(self.x.check(hasx2), [])

    def test_ValidNonceRO(self):
        hasx2 = dict()
        hasx2['content-security-policy-report-only'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
        self.assertEqual(self.y.check(hasx2), [])


if __name__ == '__main__':
    unittest.main()

