from burp import IBurpExtender,IScannerCheck, IScanIssue
from urlparse import urlparse
import securityheaders
from securityheaders import CSPVersion, FindingSeverity, SecurityHeaders
from array import array

class BurpExtender(IBurpExtender, IScannerCheck):

    def __init__(self):
        self.api = SecurityHeaders()
        self.analyzed = dict()

    def getOptions(self):
        options = dict()
        options['checks'] = ['Checker']
        options['unwanted'] = ['InfoCollector','HeaderMissingChecker']
        options['CSPFlashObjectWhitelistBypassChecker'] = dict()
        options['CSPFlashObjectWhitelistBypassChecker']['bypasses']=  ['//vk.com/swf/video.swf', '//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf']

        options['CSPScriptWhitelistBypassChecker'] = dict()
        options['CSPScriptWhitelistBypassChecker']['jsonp']= ['//bebezoo.1688.com/fragment/index.htm', '//www.google-analytics.com/gtm/js', '//googleads.g.doubleclick.net/pagead/conversion/1036918760/wcm', '//www.googleadservices.com/pagead/conversion/1070110417/wcm', '//www.google.com/tools/feedback/escalation-options', '//pin.aliyun.com/check_audio', '//offer.alibaba.com/market/CID100002954/5/fetchKeyword.do', '//ccrprod.alipay.com/ccr/arriveTime.json', '//group.aliexpress.com/ajaxAcquireGroupbuyProduct.do', '//detector.alicdn.com/2.7.3/index.php', '//suggest.taobao.com/sug', '//translate.google.com/translate_a/l', '//count.tbcdn.cn//counter3', '//wb.amap.com/channel.php', '//translate.googleapis.com/translate_a/l', '//afpeng.alimama.com/ex', '//accounts.google.com/o/oauth2/revoke', '//pagead2.googlesyndication.com/relatedsearch', '//yandex.ru/soft/browsers/check', '//api.facebook.com/restserver.php', '//mts0.googleapis.com/maps/vt', '//syndication.twitter.com/widgets/timelines/765840589183213568', '//www.youtube.com/profile_style', '//googletagmanager.com/gtm/js', '//mc.yandex.ru/watch/24306916/1', '//share.yandex.net/counter/gpp/', '//ok.go.mail.ru/lady_on_lady_recipes_r.json', '//d1f69o4buvlrj5.cloudfront.net/__efa_15_1_ornpba.xekq.arg/optout_check', '//www.googletagmanager.com/gtm/js', '//api.vk.com/method/wall.get', '//www.sharethis.com/get-publisher-info.php', '//google.ru/maps/vt', '//pro.netrox.sc/oapi/h_checksite.ashx', '//vimeo.com/api/oembed.json/', '//de.blog.newrelic.com/wp-admin/admin-ajax.php', '//ajax.googleapis.com/ajax/services/search/news', '//ssl.google-analytics.com/gtm/js', '//pubsub.pubnub.com/subscribe/demo/hello_world/', '//pass.yandex.ua/services', '//id.rambler.ru/script/topline_info.js', '//m.addthis.com/live/red_lojson/100eng.json', '//passport.ngs.ru/ajax/check', '//catalog.api.2gis.ru/ads/search', '//gum.criteo.com/sync', '//maps.google.com/maps/vt', '//ynuf.alipay.com/service/um.json', '//securepubads.g.doubleclick.net/gampad/ads', '//c.tiles.mapbox.com/v3/texastribune.tx-congress-cvap/6/15/26.grid.json', '//rexchange.begun.ru/banners', '//an.yandex.ru/page/147484', '//links.services.disqus.com/api/ping', '//api.map.baidu.com/', '//tj.gongchang.com/api/keywordrecomm/', '//data.gongchang.com/livegrail/', '//ulogin.ru/token.php', '//beta.gismeteo.ru/api/informer/layout.js/120x240-3/ru/', '//maps.googleapis.com/maps/api/js/GeoPhotoService.GetMetadata', '//a.config.skype.com/config/v1/Skype/908_1.33.0.111/SkypePersonalization', '//maps.beeline.ru/w', '//target.ukr.net/', '//www.meteoprog.ua/data/weather/informer/Poltava.js', '//cdn.syndication.twimg.com/widgets/timelines/599200054310604802', '//wslocker.ru/client/user.chk.php', '//community.adobe.com/CommunityPod/getJSON', '//maps.google.lv/maps/vt', '//dev.virtualearth.net/REST/V1/Imagery/Metadata/AerialWithLabels/26.318581', '//awaps.yandex.ru/10/8938/02400400.', '//a248.e.akamai.net/h5.hulu.com/h5.mp4', '//nominatim.openstreetmap.org/', '//plugins.mozilla.org/en-us/plugins_list.json', '//h.cackle.me/widget/32153/bootstrap', '//graph.facebook.com/1/', '//fellowes.ugc.bazaarvoice.com/data/reviews.json', '//widgets.pinterest.com/v3/pidgets/boards/ciciwin/hedgehog-squirrel-crafts/pins/', '//appcenter.intuit.com/Account/LogoutJSONP', '//www.linkedin.com/countserv/count/share', '//se.wikipedia.org/w/api.php', '//cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js', '//relap.io/api/v2/similar_pages_jsonp.js', '//c1n3.hypercomments.com/stream/subscribe', '//maps.google.de/maps/vt', '//books.google.com/books', '//connect.mail.ru/share_count', '//tr.indeed.com/m/newjobs', '//www-onepick-opensocial.googleusercontent.com/gadgets/proxy', '//www.panoramio.com/map/get_panoramas.php', '//client.siteheart.com/streamcli/client', '//www.facebook.com/restserver.php', '//autocomplete.travelpayouts.com/avia', '//www.googleapis.com/freebase/v1/topic/m/0344_', '//mts1.googleapis.com/mapslt/ft', '//api.twitter.com/1/statuses/oembed.json', '//fast.wistia.com/embed/medias/o75jtw7654.json', '//partner.googleadservices.com/gampad/ads', '//pass.yandex.ru/services', '//gupiao.baidu.com/stocks/stockbets', '//widget.admitad.com/widget/init', '//api.instagram.com/v1/tags/partykungen23328/media/recent', '//video.media.yql.yahoo.com/v1/video/sapi/streams/063fb76c-6c70-38c5-9bbc-04b7c384de2b', '//ib.adnxs.com/jpt', '//pass.yandex.com/services', '//www.google.de/maps/vt', '//clients1.google.com/complete/search', '//api.userlike.com/api/chat/slot/proactive/', '//www.youku.com/index_cookielist/s/jsonp', '//mt1.googleapis.com/mapslt/ft', '//api.mixpanel.com/track/', '//wpd.b.qq.com/cgi/get_sign.php', '//pipes.yahooapis.com/pipes/pipe.run', '//gdata.youtube.com/feeds/api/videos/WsJIHN1kNWc', '//9.chart.apis.google.com/chart', '//cdn.syndication.twitter.com/moments/709229296800440320', '//api.flickr.com/services/feeds/photos_friends.gne', '//cbks0.googleapis.com/cbk', '//www.blogger.com/feeds/5578653387562324002/posts/summary/4427562025302749269', '//query.yahooapis.com/v1/public/yql', '//kecngantang.blogspot.com/feeds/posts/default/-/Komik', '//www.travelpayouts.com/widgets/50f53ce9ada1b54bcc000031.json', '//i.cackle.me/widget/32586/bootstrap', '//translate.yandex.net/api/v1.5/tr.json/detect', '//a.tiles.mapbox.com/v3/zentralmedia.map-n2raeauc.jsonp', '//maps.google.ru/maps/vt', '//c1n2.hypercomments.com/stream/subscribe', "//rec.ydf.yandex.ru/cookie'"]

        options['CSPScriptWhitelistBypassChecker']['angular'] = ['//gstatic.com/fsn/angular_js-bundle1.js', '//www.gstatic.com/fsn/angular_js-bundle1.js', '//www.googleadservices.com/pageadimg/imgad', '//yandex.st/angularjs/1.2.16/angular-cookies.min.js', '//yastatic.net/angularjs/1.2.23/angular.min.js', '//yuedust.yuedu.126.net/js/components/angular/angular.js', '//art.jobs.netease.com/script/angular.js', '//csu-c45.kxcdn.com/angular/angular.js', '//elysiumwebsite.s3.amazonaws.com/uploads/blog-media/rockstar/angular.min.js', '//inno.blob.core.windows.net/new/libs/AngularJS/1.2.1/angular.min.js', '//gift-talk.kakao.com/public/javascripts/angular.min.js', '//ajax.googleapis.com/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js', '//master-sumok.ru/vendors/angular/angular-cookies.js', '//ayicommon-a.akamaihd.net/static/vendor/angular-1.4.2.min.js', '//pangxiehaitao.com/framework/angular-1.3.9/angular-animate.min.js', '//cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js', '//96fe3ee995e96e922b6b-d10c35bd0a0de2c718b252bc575fdb73.ssl.cf1.rackcdn.com/angular.js', '//oss.maxcdn.com/angularjs/1.2.20/angular.min.js', '//reports.zemanta.com/smedia/common/angularjs/1.2.11/angular.js', '//cdn.shopify.com/s/files/1/0225/6463/t/1/assets/angular-animate.min.js', '//parademanagement.com.s3-website-ap-southeast-1.amazonaws.com/js/angular.min.js', '//cdn.jsdelivr.net/angularjs/1.1.2/angular.min.js', '//eb2883ede55c53e09fd5-9c145fb03d93709ea57875d307e2d82e.ssl.cf3.rackcdn.com/components/angular-resource.min.js', '//andors-trail.googlecode.com/git/AndorsTrailEdit/lib/angular.min.js', '//cdn.walkme.com/General/EnvironmentTests/angular/angular.min.js', '//laundrymail.com/angular/angular.js', '//s3-eu-west-1.amazonaws.com/staticancpa/js/angular-cookies.min.js', '//collade.demo.stswp.com/js/vendor/angular.min.js', '//mrfishie.github.io/sailor/bower_components/angular/angular.min.js', '//askgithub.com/static/js/angular.min.js', '//services.amazon.com/solution-providers/assets/vendor/angular-cookies.min.js', '//raw.githubusercontent.com/angular/code.angularjs.org/master/1.0.7/angular-resource.js', '//prb-resume.appspot.com/bower_components/angular-animate/angular-animate.js', '//dl.dropboxusercontent.com/u/30877786/angular.min.js', '//static.tumblr.com/x5qdx0r/nPOnngtff/angular-resource.min_1_.js', '//storage.googleapis.com/assets-prod.urbansitter.net/us-sym/assets/vendor/angular-sanitize/angular-sanitize.min.js', '//twitter.github.io/labella.js/bower_components/angular/angular.min.js', '//cdn2-casinoroom.global.ssl.fastly.net/js/lib/angular-animate.min.js', '//www.adobe.com/devnet-apps/flashshowcase/lib/angular/angular.1.1.5.min.js', '//eternal-sunset.herokuapp.com/bower_components/angular/angular.js', "//cdn.bootcss.com/angular.js/1.2.0/angular.min.js'"]

        options['CSPScriptWhitelistBypassChecker']['jsonpeval'] = ['googletagmanager.com', 'www.googletagmanager.com', 'www.googleadservices.com', 'google-analytics.com', 'ssl.google-analytics.com', 'www.google-analytics.com']

        return options

    def registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Advanced Security Headers")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

        self._options = self.getOptions()

 
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (isinstance(existingIssue, CustomScanIssue) and isinstance(newIssue, CustomScanIssue) and existingIssue._name == newIssue._name):
            return -1
        else:
            return 0

    def _get_matches(self, response, headers, findings):
        matches = []
        reslen = len(response)
        for finding in findings:
            header = str(finding.header)
            directive = str(finding.directive)
            value = str(finding.value)
            matchlen = len(value) if value else len(directive)
            ftype = str(finding.ftype)
            for head in headers:
                kv = head.lower().split(":",1)
                if str(kv[0].lower()) == str(header):
                    headerstart = self._helpers.indexOf(response,bytearray(header), False, 0, reslen)
                    headerend = headerstart+len(bytearray(header))
                    matches.append(array('i',[headerstart,headerend]))
                    directivestart = self._helpers.indexOf(response,bytearray(directive),False,headerstart,reslen)
                    directiveend = directivestart+len(bytearray(directive))
                    if directivestart != -1 and directivestart != headerstart:
                        matches.append(array('i',[directivestart,directiveend]))
                    else:
                        directivestart = headerstart
                    if value:
                        valuestart = self._helpers.indexOf(response,bytearray(value),False,directivestart,reslen)
                        valueend = valuestart+len(bytearray(value))
                        if valuestart != -1 and valuestart != directivestart:
                            matches.append(array('i',[valuestart,valueend]))
        return matches


    def doPassiveScan(self, baseRequestResponse):
        response = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        request = self._helpers.analyzeRequest(baseRequestResponse)
        headers = list(response.getHeaders())
        host = urlparse(str(request.getUrl())).netloc
        if host not in self.analyzed.keys():
            self.analyzed[host] = list()
        toanalyze = list()
        for header in headers:
            if header not in self.analyzed[host]:
                toanalyze.append(header)
        self.analyzed[host].extend(toanalyze)

        findings = self.api.check_headers_with_list(toanalyze, self.getOptions())
        if not findings or len(findings) == 0:
            return None



        result = list()
        for finding in findings:
            if not "none" in str(finding.severity).lower() and not "missing_header" in str(finding.ftype).lower():
                try:
                    matches = [self._callbacks.applyMarkers(baseRequestResponse, None,self._get_matches(baseRequestResponse.getResponse(),response.getHeaders(),[finding]))]
                except:
                    matches = None                
                result.append(CustomScanIssue(baseRequestResponse.getHttpService(),request.getUrl(),matches,finding))
        return result

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass


#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = "Certain"

    def __init__(self,  httpService, url, httpMessages, finding):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self.assignSeverity(finding)
        self.assignConfidence(finding)
        val = finding.description
        self._name = "Insecure " + str(finding.header) +": " +  str(finding.ftype).lower().replace('_', ' ')
        self._detail = val
        self._finding = finding

    def __eq__(self, other):
        if isinstance(other, CustomScanIssue):
            return self._finding == other._finding   
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def assignSeverity(self, finding):
        if finding.severity == FindingSeverity.MEDIUM or finding.severity == FindingSeverity.MEDIUM_MAYBE:
            self._severity = "Medium"
        elif finding.severity == FindingSeverity.HIGH or finding.severity == FindingSeverity.HIGH_MAYBE:
            self._severity = "High"
        elif finding.severity == FindingSeverity.LOW:
            self._severity = "Low"
        elif finding.severity == FindingSeverity.SYNTAX or finding.severity == FindingSeverity.STRICT_CSP or finding.severity == FindingSeverity.INFO:
            self._severity = "Information"
        else:
            self._severity = "Information"
    
    def assignConfidence(self, finding):
        if finding.severity == FindingSeverity.MEDIUM_MAYBE or finding.severity == FindingSeverity.HIGH_MAYBE:
            self._confidence = "Tentative"
        else:
            self._confidence = "Certain"

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getRawFinding(self):
        return self._finding

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
