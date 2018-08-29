
import unittest

from securityheaders.checkers.featurepolicy import FeaturePolicyWildCardChecker

class WildCardTest(unittest.TestCase):
    def setUp(self):
       self.x = FeaturePolicyWildCardChecker()

    def test_checkNo(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNone(self):
       hasx = dict()
       hasx['feature-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_wildCard(self):
       hasx5 = dict()
       hasx5['feature-policy'] = 'camera *'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_NoWildCard(self):
       hasx4 = dict()
       hasx4['feature-policy'] = "camera 'self'"
       self.assertEquals(self.x.check(hasx4), [])

if __name__ == '__main__':
    unittest.main()
