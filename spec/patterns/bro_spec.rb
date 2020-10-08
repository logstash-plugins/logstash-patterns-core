# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "BRO_HTTP", ['legacy', 'ecs-v1'] do

  let(:message) do
    "1432555199.633017	COpk6E3vkURP8QQNKl	192.168.9.35	55281	178.236.7.146	80	4	POST	www.amazon.it	/xa/dealcontent/v2/GetDeals?nocache=1432555199326	http://www.amazon.it/	Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36	223	1859	200	OK	-	-	-	(empty)	-	-	-	FrLEcY3AUPKdcYGf29	text/plain	FOJpbGzIMh9syPxH8	text/plain"
  end

  it "matches a simple message" do
    expect(pattern).to match(message)
  end
  
  it "generates the ts field" do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1432555199.633017")
    else
      expect(grok).to include("ts" => "1432555199.633017")
    end
  end

  it "generates the uid field" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("session_id" => "COpk6E3vkURP8QQNKl"))
    else
      expect(grok).to include("uid" => "COpk6E3vkURP8QQNKl")
    end
  end

  it "generates the orig_ fields" do
    if ecs_compatibility?
      expect(grok).to include("source" => { "ip" => "192.168.9.35", "port" => 55281 })
    else
      expect(grok).to include("orig_h" => "192.168.9.35", "orig_p" => "55281")
    end
  end

  it "generates the resp_ fields" do
    if ecs_compatibility?
      expect(grok).to include("destination" => { "ip" => "178.236.7.146", "port" => 80 })

    else
      expect(grok).to include("resp_h" => "178.236.7.146", "resp_p" => "80")
    end
  end

  it "generates the trans_depth field" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("http" => hash_including("trans_depth" => 4)))
    else
      expect(grok).to include("trans_depth" => "4")
    end
  end

  it "generates the method/referrer field" do
    if ecs_compatibility?
      expect(grok).to include("http" => hash_including("request" => hash_including("method" => "POST", "referrer" => "http://www.amazon.it/" )))
    else
      expect(grok).to include("method" => "POST")
      expect(grok).to include("referrer" => "http://www.amazon.it/")
    end
  end

  it "generates the domain/uri/referrer & username/password field" do
    if ecs_compatibility?
      expect(grok).to include("url" => hash_including("domain" => "www.amazon.it"))
      expect(grok).to include("url" => hash_including("original" => "/xa/dealcontent/v2/GetDeals?nocache=1432555199326"))

      expect(grok['url'].keys).to_not include("username", "password")
    else
      expect(grok).to include("domain" => "www.amazon.it")
      expect(grok).to include("uri" => "/xa/dealcontent/v2/GetDeals?nocache=1432555199326")

      expect(grok).to include("username" => "-")
      expect(grok).to include("password" => "-")
    end
  end

  it "generates the user_agent field" do
    if ecs_compatibility?
      expect(grok).to include("user_agent" => { "original" => "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" })
    else
      expect(grok).to include("user_agent" => "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36")
    end
  end

  it "generates the request_body_len/response_body_len fields" do
    if ecs_compatibility?
      expect(grok).to include("http" => hash_including("request" => hash_including("body" => { "bytes" => 223 })))
      expect(grok).to include("http" => hash_including("response" => hash_including("body" => { "bytes" => 1859 })))
    else
      expect(grok).to include("request_body_len" => "223")
      expect(grok).to include("response_body_len" => "1859")
    end
  end

  it "generates the status_ fields" do
    if ecs_compatibility?
      expect(grok).to include("http" => hash_including("response" => hash_including("status_code" => 200)))
      expect(grok).to include("zeek" => hash_including("http" => hash_including("status_msg" => "OK")))
    else
      expect(grok).to include("status_code" => "200", "status_msg" => "OK")
    end
  end

  it "generates the info_ fields" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("info_code", "info_msg")
    else
      expect(grok).to include("info_code" => "-", "info_msg" => "-")
    end
  end

  it "generates the filename field" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("filename")
    else
      expect(grok).to include("filename" => "-")
    end
  end

  it "generates the bro_tags field" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("tags")
    else
      expect(grok).to include("bro_tags" => "(empty)")
    end
  end

  it "generates the proxied field" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("proxied")
    else
      expect(grok).to include("proxied" => "-")
    end
  end

  it "generates the orig_ fields" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("http" => hash_including("orig_fuids" => "FrLEcY3AUPKdcYGf29")))
      expect(grok).to include("zeek" => hash_including("http" => hash_including("orig_mime_types" => "text/plain")))
    else
      expect(grok).to include("orig_fuids" => "FrLEcY3AUPKdcYGf29")
      expect(grok).to include("orig_mime_types" => "text/plain")
    end
  end

  it "generates the resp_ fields" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("http" => hash_including("resp_fuids" => "FOJpbGzIMh9syPxH8")))
      expect(grok).to include("zeek" => hash_including("http" => hash_including("resp_mime_types" => "text/plain")))
    else
      expect(grok).to include("resp_fuids" => "FOJpbGzIMh9syPxH8")
      expect(grok).to include("resp_mime_types" => "text/plain")
    end
  end

end
