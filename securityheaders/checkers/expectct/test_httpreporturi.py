import unittest

from securityheaders.checkers.expectct import ExpectCTHTTPReportURIChecker

class ExpectCTHTTPReportURICheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = ExpectCTHTTPReportURIChecker()

    def test_check(self):
        xempty = dict()
        self.assertEqual(self.x.check(xempty), [])

    def test_checkNone(self):
        xnone = None
        self.assertEqual(self.x.check(xnone), [])

    def test_Good(self):
        xhas = dict()
        xhas['expect-ct'] = 'max-age=10, enforce, report-uri=https://google.com/report'
        self.assertEqual(self.x.check(xhas), [])

    def test_Bad(self):
        xhasbad = dict()
        xhasbad['expect-ct'] = 'max-age=10, enforce, report-uri=http://google.com/report'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
if __name__ == '__main__':
    unittest.main()
