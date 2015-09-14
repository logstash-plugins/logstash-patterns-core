# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "HTTPD_COMMONLOG" do

  context "COMMONAPACHELOG", "Typical test case" do

    let(:value) { '83.149.9.216 - - [24/Feb/2015:23:13:42 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36'}

    it "generates the clientip field" do
      expect(grok_match(subject, value)).to include("clientip" => "83.149.9.216")
    end

  end

  context "COMMONAPACHELOG", "Email address in auth field" do

    let(:value) { '10.0.0.1 - username@example.com [07/Apr/2016:18:42:24 +0000] "GET /bar/foo/users/1/username%40example.com/authenticate?token=blargh&client_id=15 HTTP/1.1" 400 75 "" "Mozilla/5.0 (iPad; CPU OS 9_3_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E238 Safari/601.1"'}

    it "generates the clientip field" do
      expect(grok_match(subject, value)).to include("auth" => "username@example.com")
    end

  end

end

describe "HTTPD_ERRORLOG" do

  it "matches a full httpd 2.4 message" do
    expect(subject).to match("[Mon Aug 31 09:30:48.958285 2015] [proxy_fcgi:error] [pid 28787:tid 140169587934976] (70008)Partial results are valid but processing is incomplete: [client 58.13.45.166:59307] AH01075: Error dispatching request to : (reading input brigade), referer: http://example.com/index.php?id_product=11&controller=product")
  end

  it "matches a httpd 2.2 log message" do
    expect(subject).to match("[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com")
  end

  it "matches a short httpd 2.4 message" do
    expect(subject).to match("[Mon Aug 31 07:15:38.664897 2015] [proxy_fcgi:error] [pid 28786:tid 140169629898496] [client 81.139.1.34:52042] AH01071: Got error 'Primary script unknown\n'")
  end

  it "matches an httpd 2.4 restart" do
    expect(subject).to match("[Mon Aug 31 06:29:47.406518 2015] [mpm_event:notice] [pid 24968:tid 140169861986176] AH00489: Apache/2.4.16 (Ubuntu) configured -- resuming normal operations")
    expect(subject).to match("[Mon Aug 31 06:29:47.406530 2015] [core:notice] [pid 24968:tid 140169861986176] AH00094: Command line: '/usr/sbin/apache2'")
  end

end
