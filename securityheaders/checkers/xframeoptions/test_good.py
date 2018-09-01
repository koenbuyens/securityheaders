import unittest
from securityheaders.checkers.xframeoptions import XFrameOptionsNotAllowFromChecker

class XFrameOptionsCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = XFrameOptionsNotAllowFromChecker()

    def test_checkNoCSP(self):
        xempty = dict()
        self.assertEqual(self.x.check(xempty), [])

    def test_checkNone(self):
        xnone = None
        self.assertEqual(self.x.check(xnone), [])

    def test_Good(self):
        xhas = dict()
        xhas['x-frame-options'] = 'deny'
        self.assertEqual(self.x.check(xhas), [])

    def test_Bad(self):
        xhasbad = dict()
        xhasbad['x-frame-options'] = 'allow-from google.com'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_None(self):
        xhasNone = dict()
        xhasNone['x-frame-options'] = None
        self.assertEqual(self.x.check(xhasNone), [])


if __name__ == '__main__':
    unittest.main()
