
import unittest

from securityheaders.checkers.xxssprotection import XXSSProtectionHTTPSReportChecker

class XXSSProtectionHTTPSReportCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = XXSSProtectionHTTPSReportChecker()

    def test_checkNoCSP(self):
        xempty = dict()
        self.assertEqual(self.x.check(xempty), [])

    def test_checkNone(self):
        xnone = None
        self.assertEqual(self.x.check(xnone), [])

    def test_Good(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1'
        self.assertEqual(self.x.check(xhas), [])

    def test_Good2(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1; mode=block'
        self.assertEqual(self.x.check(xhas), [])

    def test_Good3(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1; report=https://example.com/rep'
        self.assertEqual(self.x.check(xhas), [])

    def test_HTTP(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1; report=http://example.com/repo'
        result = self.x.check(xhas)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

if __name__ == '__main__':
    unittest.main()
