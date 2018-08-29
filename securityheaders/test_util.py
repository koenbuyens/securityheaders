import unittest
from urlparse import urlparse
from securityheaders import Util

class UtilTest(unittest.TestCase):
    def test_isUrlSchemeNone(self):
        self.assertFalse(Util.isUrlScheme(None))

    def test_isUrlSchemeHttp(self):
        self.assertTrue(Util.isUrlScheme('http:'))

    def test_isUrlSchemeHttps(self):
        self.assertTrue(Util.isUrlScheme('https:'))

    def test_isUrlSchemeInvalid(self):
        self.assertFalse(Util.isUrlScheme('noscheme'))
        
    def test_getSchemeFreeUrlValid(self):
        self.assertEqual(Util.getSchemeFreeUrl('http://www.synopsys.com'), 'www.synopsys.com')

    def test_getSchemeFreeUrlCapitals(self):
        self.assertEqual(Util.getSchemeFreeUrl('HTTPS://www.synopsys.com'), 'www.synopsys.com')

    def test_getSchemeFreeUrlNone(self):
        self.assertEqual(Util.getSchemeFreeUrl(None), None)

    def test_matchWildcardUrls(self):
        urls = [
        '//vk.com/swf/video.swf',
        '//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'

        ]
        self.assertEquals(Util.matchWildcardUrls('https://*.vk.com', urls), None)
        self.assertEquals(Util.matchWildcardUrls('https://ajax.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))
        self.assertEquals(Util.matchWildcardUrls('https://*.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))
        self.assertEquals(Util.matchWildcardUrls(None, urls), None)
        self.assertEquals(Util.matchWildcardUrls('https://*.googleapis.com', None), None)
        self.assertEquals(Util.matchWildcardUrls('https://*.googleapis.com', []), None)
#        self.assertEquals(Util.matchWildcardUrls('*.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))


if __name__ == '__main__':
    unittest.main()
