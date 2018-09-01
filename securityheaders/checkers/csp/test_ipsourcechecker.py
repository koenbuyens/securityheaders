import unittest


from securityheaders.checkers.csp import CSPIPSourceChecker, CSPReportOnlyIPSourceChecker


class IPSourceTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPIPSourceChecker()
       self.y = CSPReportOnlyIPSourceChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_NoneCsp(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_IpSource(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src 127.0.0.1'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
    
    def test_NoneCspRO(self):
        hasx = dict()
        hasx['content-security-policy-report-only'] = None
        self.assertEqual(self.y.check(hasx), [])
    
    def test_IpSourceRO(self):
        hasx5 = dict()
        hasx5['content-security-policy-report-only'] = 'script-src 127.0.0.1'
        result = self.y.check(hasx5)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_IpSource2(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = 'script-src 200.200.200.200'
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_URI(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       self.assertEqual(self.x.check(hasx3), [])

    def test_URI2(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEqual(self.x.check(hasx2), [])


if __name__ == '__main__':
    unittest.main()
