# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "HTTPD_COMBINEDLOG" do

  context "HTTPD_COMBINEDLOG", "Typical test case" do

    let(:value) { '83.149.9.216 - - [24/Feb/2015:23:13:42 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"'}

    it "generates the clientip field" do
      expect(grok_match(subject, value)).to include(
        'clientip' => '83.149.9.216',
        'verb' => 'GET',
        'request' => '/presentations/logstash-monitorama-2013/images/kibana-search.png',
        'httpversion' => '1.1',
        'response' => '200',
        'bytes' => '203023',
        'referrer' => '"http://semicomplete.com/presentations/logstash-monitorama-2013/"',
        'agent' => '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"'
      )
    end

  end

  context "HTTPD_COMBINEDLOG", "Email address in auth field" do

    let(:value) { '10.0.0.1 - username@example.com [07/Apr/2016:18:42:24 +0000] "GET /bar/foo/users/1/username%40example.com/authenticate?token=blargh&client_id=15 HTTP/1.1" 400 75 "" "Mozilla/5.0 (iPad; CPU OS 9_3_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E238 Safari/601.1"'}

    it "generates the clientip field" do
      expect(grok_match(subject, value)).to include("auth" => "username@example.com")
    end

  end

end

describe "HTTPD_ERRORLOG" do

  context "HTTPD_ERRORLOG", "matches a full httpd 2.4 message" do
    let(:value) {
      "[Mon Aug 31 09:30:48.958285 2015] [proxy_fcgi:error] [pid 28787:tid 140169587934976] (70008)Partial results are valid but processing is incomplete: [client 58.13.45.166:59307] AH01075: Error dispatching request to : (reading input brigade), referer: http://example.com/index.php?id_product=11&controller=product"
    }
    it "generates the fields" do

      expect(grok_match(subject, value)).to include(
        'timestamp' => 'Mon Aug 31 09:30:48.958285 2015',
        'module' => 'proxy_fcgi',
        'loglevel' => 'error',
        'pid' => '28787',
        'tid' => '140169587934976',
        'proxy_errorcode' => '70008',
        'proxy_message' => 'Partial results are valid but processing is incomplete',
        'clientip' => '58.13.45.166',
        'clientport' => '59307',
        'errorcode' => 'AH01075',
        'message' => [ value, 'Error dispatching request to : (reading input brigade), referer: http://example.com/index.php?id_product=11&controller=product' ],
      )
    end
  end

  context "HTTPD_ERRORLOG", "matches a httpd 2.2 log message" do
    let(:value) {
      "[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com"
    }
    it "generates the fields" do
      expect(grok_match(subject, value)).to include(
        'timestamp' => 'Mon Aug 31 16:27:04 2015',
        'loglevel' => 'error',
        'clientip' => '10.17.42.3',
        'message' => [ value, 'Premature end of script headers: example.com' ]
      )
    end
  end

  context "HTTPD_ERRORLOG", "matches a short httpd 2.4 message" do
    let(:value1) {
      "[Mon Aug 31 07:15:38.664897 2015] [proxy_fcgi:error] [pid 28786:tid 140169629898496] [client 81.139.1.34:52042] AH01071: Got error 'Primary script unknown\n'"
    }
    it "generates the fields" do
      expect(grok_match(subject, value1)).to include(
        'timestamp' => 'Mon Aug 31 07:15:38.664897 2015',
        'module' => 'proxy_fcgi',
        'loglevel' => 'error',
        'pid' => '28786',
        'tid' => '140169629898496',
        'clientip' => '81.139.1.34',
        'clientport' => '52042',
        'errorcode' => 'AH01071',
        'message' => [ value1, "Got error 'Primary script unknown\n'" ]
      )
    end

    let(:value2) {
      "[Thu Apr 27 10:39:46.719636 2017] [php7:notice] [pid 17] [client 10.255.0.3:49580] Test error log record"
    }
	it "generates the fields" do
      expect(grok_match(subject, value2)).to include(
        'timestamp' => 'Thu Apr 27 10:39:46.719636 2017',
        'module' => 'php7',
        'loglevel' => 'notice',
        'pid' => '17',
        'clientip' => '10.255.0.3',
        'clientport' => '49580',
        'message' => [ value2, "Test error log record" ]
      )
    end
  end

  context "HTTPD_ERRORLOG", "matches an httpd 2.4 restart" do
    let(:value1) {
      "[Mon Aug 31 06:29:47.406518 2015] [mpm_event:notice] [pid 24968:tid 140169861986176] AH00489: Apache/2.4.16 (Ubuntu) configured -- resuming normal operations"
    }
    it "generates the fields" do
      expect(grok_match(subject, value1)).to include(
        'timestamp' => 'Mon Aug 31 06:29:47.406518 2015',
        'module' => 'mpm_event',
        'loglevel' => 'notice',
        'pid' => '24968',
        'tid' => '140169861986176',
        'errorcode' => 'AH00489',
        'message' => [ value1, 'Apache/2.4.16 (Ubuntu) configured -- resuming normal operations' ]
      )
    end

    let(:value2) {
      "[Mon Aug 31 06:29:47.406530 2015] [core:notice] [pid 24968:tid 140169861986176] AH00094: Command line: '/usr/sbin/apache2'"
    }
    it "generates the fields" do
      expect(grok_match(subject, value2)).to include(
        'timestamp' => 'Mon Aug 31 06:29:47.406530 2015',
        'module' => 'core',
        'loglevel' => 'notice',
        'pid' => '24968',
        'tid' => '140169861986176',
        'errorcode' => 'AH00094',
        'message' => [ value2, 'Command line: \'/usr/sbin/apache2\'' ]
      )
    end
  end

  
end
