import unittest

from securityheaders.checkers.xxssprotection import XXSSProtectionBlockChecker

class XXSSProtectionBlockCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = XXSSProtectionBlockChecker()

    def test_checkNoCSP(self):
        xempty = dict()
        self.assertEquals(self.x.check(xempty), [])

    def test_checkNone(self):
        xnone = None
        self.assertEquals(self.x.check(xnone), [])

    def test_Good(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1'
        self.assertEquals(self.x.check(xhas), [])

    def test_Good2(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1; mode=block'
        self.assertEquals(self.x.check(xhas), [])

    def test_Good3(self):
        xhas = dict()
        xhas['x-xss-protection'] = '1; report=https://example.com/rep'
        self.assertEquals(self.x.check(xhas), [])

    def test_NotEnabled(self):
        xhas = dict()
        xhas['x-xss-protection'] = '0'
        result = self.x.check(xhas)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

if __name__ == '__main__':
    unittest.main()
