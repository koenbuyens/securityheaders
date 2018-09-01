from securityheaders.models.featurepolicy import FeaturePolicy, FeaturePolicyKeyword, FeaturePolicyDirective
import unittest

class FeaturePolicyTest(unittest.TestCase):
    def setUp(self):
        self.fpgeolocation = FeaturePolicy("geolocation 'none'")
        self.fpcomplex = FeaturePolicy("unsized-media 'none'; geolocation 'self' https://example.com; camera *;")

    def test_parsing(self):
        geo = self.fpcomplex.getEffectiveValues(FeaturePolicyDirective.GEOLOCATION)
        self.assertTrue(FeaturePolicyKeyword.SELF in geo)
        self.assertTrue("https://example.com" in geo)
        self.assertEqual(len(geo), 2)


if __name__ == '__main__':
    unittest.main()
