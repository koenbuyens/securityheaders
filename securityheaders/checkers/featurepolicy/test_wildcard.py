
import unittest

from securityheaders.checkers.featurepolicy import FeaturePolicyWildCardChecker

class WildCardTest(unittest.TestCase):
    def setUp(self):
       self.x = FeaturePolicyWildCardChecker()

    def test_checkNo(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_checkNone(self):
       hasx = dict()
       hasx['feature-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_wildCard(self):
       hasx5 = dict()
       hasx5['feature-policy'] = 'camera *'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_NoWildCard(self):
       hasx4 = dict()
       hasx4['feature-policy'] = "camera 'self'"
       self.assertEqual(self.x.check(hasx4), [])

if __name__ == '__main__':
    unittest.main()
