# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "HTTPD_COMBINEDLOG", ['legacy', 'ecs-v1'] do

  context "typical test case" do

    let(:message) { '83.149.9.216 - - [24/Feb/2015:23:13:42 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"'}

    it "matches" do
      if ecs_compatibility?
        expect(grok).to include(
                            "http" => {
                                "request" => {
                                    "method" => "GET",
                                    "referrer" => "http://semicomplete.com/presentations/logstash-monitorama-2013/"
                                },
                                "response" => {
                                    "body" => { "bytes" => 203023 },
                                    "status_code" => 200
                                },
                                "version"=>"1.1"
                            },
                            "source" => { "address" => "83.149.9.216" },
                            "url" => { "original" => "/presentations/logstash-monitorama-2013/images/kibana-search.png" },
                            "user_agent" => { "original" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36" }
                        )
      else
        expect(grok).to include(
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

    it "does not capture 'null' fields" do
      if ecs_compatibility?
        expect(grok.keys).to_not include('user') # 'user' => 'name'
        expect(grok.keys).to_not include('apache') # apache.access.user.identity
      else
        expect(grok).to include('auth' => '-', 'ident' => '-')
      end
    end

  end

  context "email address in auth field" do

    let(:message) { '10.0.0.1 - username@example.com [07/Apr/2016:18:42:24 +0000] "GET /bar/foo/users/1/username%40example.com/authenticate?token=blargh&client_id=15 HTTP/1.1" 400 75 "" "Mozilla/5.0 (iPad; CPU OS 9_3_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13E238 Safari/601.1"'}

    it "gets captured" do
      if ecs_compatibility?
        expect(grok).to include("user" => { 'name' => "username@example.com" })
      else
        expect(grok).to include("auth" => "username@example.com")
      end
    end

  end

  context 'sample OPTIONS line' do

    let(:message) { '83.149.9.216 - a.user [11/Jan/2020:23:05:27 +0100] "OPTIONS /remote.php/ HTTP/1.1" - 7908 "-" "monitoring-client (v2.2)"' }

    it 'matches' do
      if ecs_compatibility?
        expect(grok).to include("http" => hash_including("response" => hash_including("body" => { "bytes" => 7908 })))
        expect(grok).to include("http" => hash_including("request" => { "method" => "OPTIONS" }, "version" => "1.1"))
        expect(grok).to include(
                            "url" => { "original" => "/remote.php/" },
                            "user_agent" => { "original" => "monitoring-client (v2.2)" }
                        )
      else
        expect(grok).to include("verb" => "OPTIONS", 'request' => '/remote.php/', 'httpversion' => '1.1', "bytes" => '7908')
      end
    end

    it 'does not capture optional response code' do
      if ecs_compatibility?
        expect(grok['http']['response'].keys).to_not include("status_code")
      else
        expect(grok.keys).to_not include("response")
      end
    end

  end

end

describe_pattern "HTTPD_ERRORLOG", ['legacy', 'ecs-v1'] do

  context "a full httpd 2.4 message" do
    let(:message) do
      "[Mon Aug 31 09:30:48.958285 2015] [proxy_fcgi:error] [pid 28787:tid 140169587934976] (70008)Partial results are valid but processing is incomplete: [client 58.13.45.166:59307] AH01075: Error dispatching request to : (reading input brigade), referer: http://example.com/index.php?id_product=11&controller=product"
    end

    it "generates the fields" do
      expect(grok).to include('timestamp' => 'Mon Aug 31 09:30:48.958285 2015')
      if ecs_compatibility?
        expect(grok).to include("log" => { "level" => "error" })
        expect(grok).to include("process" => { "pid" => 28787, "thread" => { "id" => 140169587934976 } })
        expect(grok).to include("source" => { "address"=>"58.13.45.166", "port" => 59307 })
        expect(grok).to include("error" => { "code" => 'AH01075' })
        expect(grok).to include("apache" => { "error" => {
            "module" => "proxy_fcgi",
            "proxy" => { "error" => { "code" => '70008', "message" => "Partial results are valid but processing is incomplete" }}}
        })
      else
        expect(grok).to include(
                            'timestamp' => 'Mon Aug 31 09:30:48.958285 2015',
                            'module' => 'proxy_fcgi',
                            'loglevel' => 'error',
                            'pid' => '28787',
                            'tid' => '140169587934976',
                            'proxy_errorcode' => '70008',
                            'proxy_message' => 'Partial results are valid but processing is incomplete',
                            'clientip' => '58.13.45.166',
                            'clientport' => '59307',
                            'errorcode' => 'AH01075'
                            )
      end
      expect(grok).to include('message' => [ message, 'Error dispatching request to : (reading input brigade), referer: http://example.com/index.php?id_product=11&controller=product' ])
    end
  end

  context "a httpd 2.2 log message" do
    let(:message) do
      "[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com"
    end

    it "generates the fields" do
      if ecs_compatibility?
        expect(grok).to include(
                            "timestamp"=>"Mon Aug 31 16:27:04 2015",
                            "log"=>{"level"=>"error"},
                            "source"=>{"address"=>"10.17.42.3"})
        expect(grok.keys).to_not include("error") # error.code
      else
        expect(grok).to include(
                            'timestamp' => 'Mon Aug 31 16:27:04 2015',
                            'loglevel' => 'error',
                            'clientip' => '10.17.42.3'
                        )
        expect(grok.keys).to_not include('errorcode')
      end
      expect(grok).to include('message' => [ message, 'Premature end of script headers: example.com' ])
    end
  end

  context "a short httpd 2.4 message" do
    let(:value1) {
      "[Mon Aug 31 07:15:38.664897 2015] [proxy_fcgi:error] [pid 28786:tid 140169629898496] [client 81.139.1.34:52042] AH01071: Got error 'Primary script unknown\n'"
    }
    it "generates the fields" do
      match_result = grok_match(pattern, value1)
      expect(match_result).to include('timestamp' => 'Mon Aug 31 07:15:38.664897 2015')
      if ecs_compatibility?
        expect(match_result).to include(
                                    "apache"=>{"error"=>{"module"=>"proxy_fcgi"}},
                                    "log"=>{"level"=>"error"},
                                    "process"=>{"pid"=>28786, "thread"=>{"id"=>140169629898496}},
                                    "source"=>{"address"=>"81.139.1.34", "port"=>52042},
                                    "error"=>{"code"=>"AH01071"},
                                )
      else
        expect(match_result).to include(
                                    'module' => 'proxy_fcgi',
                                    'loglevel' => 'error',
                                    'pid' => '28786',
                                    'tid' => '140169629898496',
                                    'clientip' => '81.139.1.34',
                                    'clientport' => '52042',
                                    'errorcode' => 'AH01071'
                                )
      end
      expect(match_result).to include('message' => [ value1, "Got error 'Primary script unknown\n'" ])
    end

    let(:value2) {
      "[Thu Apr 27 10:39:46.719636 2017] [php7:notice] [pid 17] [client 10.255.0.3:49580] Test error log record"
    }
	  it "generates the fields" do
      match_result = grok_match(pattern, value2)
      expect(match_result).to include('timestamp' => 'Thu Apr 27 10:39:46.719636 2017')
      if ecs_compatibility?
        expect(match_result).to include(
                                    "apache"=>{"error"=>{"module"=>"php7"}},
                                    "log"=>{"level"=>"notice"},
                                    "process"=>{"pid"=>17},
                                    "source"=>{"port"=>49580, "address"=>"10.255.0.3"}
                                )
      else
        expect(match_result).to include(
                                    'module' => 'php7',
                                    'loglevel' => 'notice',
                                    'pid' => '17',
                                    'clientip' => '10.255.0.3',
                                    'clientport' => '49580'
                                )
      end
      expect(match_result).to include('message' => [ value2, "Test error log record" ])
    end
  end

  context "a httpd 2.4 restart message" do
    let(:value1) {
      "[Mon Aug 31 06:29:47.406518 2015] [mpm_event:notice] [pid 24968:tid 140169861986176] AH00489: Apache/2.4.16 (Ubuntu) configured -- resuming normal operations"
    }
    it "generates the fields" do
      match_result = grok_match(pattern, value1)
      expect(match_result).to include('timestamp' => 'Mon Aug 31 06:29:47.406518 2015')
      if ecs_compatibility?
        expect(match_result).to include(
                                    "apache"=>{"error"=>{"module"=>"mpm_event"}},
                                    "log"=>{"level"=>"notice"},
                                    "process"=>{"pid"=>24968, "thread"=>{"id"=>140169861986176}},
                                    "error"=>{"code"=>"AH00489"}
                                )

      else
        expect(match_result).to include(
                                    'module' => 'mpm_event',
                                    'loglevel' => 'notice',
                                    'pid' => '24968',
                                    'tid' => '140169861986176',
                                    'errorcode' => 'AH00489'
                                )
      end
      expect(match_result).to include('message' => [ value1, 'Apache/2.4.16 (Ubuntu) configured -- resuming normal operations' ])
    end

    let(:value2) {
      "[Mon Aug 31 06:29:47.406530 2015] [core:notice] [pid 24968:tid 140169861986176] AH00094: Command line: '/usr/sbin/apache2'"
    }
    it "generates the fields" do
      match_result = grok_match(pattern, value2)
      expect(match_result).to include('timestamp' => 'Mon Aug 31 06:29:47.406530 2015')
      if ecs_compatibility?
        expect(match_result).to include(
                                    "apache"=>{"error"=>{"module"=>"core"}},
                                    "log"=>{"level"=>"notice"},
                                    "process"=>{"pid"=>24968, "thread"=>{"id"=>140169861986176}},
                                    "error"=>{"code"=>"AH00094"}
                                )
      else
        expect(match_result).to include(
                                    'module' => 'core',
                                    'loglevel' => 'notice',
                                    'pid' => '24968',
                                    'tid' => '140169861986176',
                                    'errorcode' => 'AH00094'
                                )
      end
      expect(match_result).to include('message' => [ value2, 'Command line: \'/usr/sbin/apache2\'' ])
    end
  end

  context "a httpd 2.4 message witout module" do
    let(:message) do
      "[Tue Apr 14 14:27:52.605084 2020] [:error] [pid 5688] [client 192.168.10.110:8196] script '/login/wp-login.php' not found or unable to stat"
    end

    it "matches" do
      expect(grok).to include('timestamp' => 'Tue Apr 14 14:27:52.605084 2020')
      if ecs_compatibility?
        expect(grok).to include("log"=>{"level" => "error"})
        expect(grok).to include("process"=>{"pid" => 5688})
        expect(grok).to include("process"=>{"pid" => 5688})
        expect( ((grok['apache'] || {})['error'] || {}).keys ).to_not include('module')
      else
        expect(grok).to include('loglevel' => 'error', 'pid' => '5688')
      end
    end
  end

  context 'a debug message' do
    let(:message) do
      '[Fri Feb 01 22:03:08.319124 2019] [authz_core:debug] [pid 9:tid 140597881775872] mod_authz_core.c(820): [client 172.17.0.1:50752] AH01626: authorization result of <RequireAny>: granted'
    end

    it 'matches imperfectly (legacy)' do
      if ecs_compatibility?
        pending
        raise NotImplementedError, "TODO: would be nice to 'improve' matching on these debug logs as well"
      else
        expect(grok).to include({
                                    "timestamp"=>"Fri Feb 01 22:03:08.319124 2019",
                                    "module"=>"authz_core",
                                    "loglevel"=>"debug",
                                    "pid"=>"9",
                                    "tid"=>"140597881775872",
                                    "errorcode"=>"mod_authz_core.c(820)",
                                    "message"=>[message, "[client 172.17.0.1:50752] AH01626: authorization result of <RequireAny>: granted"]
                                })
      end
    end
  end
  
end
