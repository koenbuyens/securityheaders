import unittest

from securityheaders.checkers.expectct import ExpectCTNotEnforcedChecker

class ExpectCTNotEnforcedCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = ExpectCTNotEnforcedChecker()

    def test_check(self):
        xempty = dict()
        self.assertEquals(self.x.check(xempty), [])

    def test_checkNone(self):
        xnone = None
        self.assertEquals(self.x.check(xnone), [])

    def test_Good(self):
        xhas = dict()
        xhas['expect-ct'] = 'max-age=500000, enforce, report-uri=https://google.com'
        self.assertEquals(self.x.check(xhas), [])

    def test_Bad(self):
        xhasbad = dict()
        xhasbad['expect-ct'] = 'max-age=20000, report-uri=https://google.com'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)
    
    def test_Bad2(self):
        xhasbad = dict()
        xhasbad['expect-ct'] = 'max-age=0, enforce, report-uri=https://google.com'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

    def test_Bad3(self):
        xhasbad = dict()
        xhasbad['expect-ct'] = 'max-age=0, report-uri=https://google.com'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 2)
    
    def test_Bad4(self):
        xhasbad = dict()
        xhasbad['expect-ct'] = 'max-age=10, enforce, report-uri=https://google.com'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

if __name__ == '__main__':
    unittest.main()
