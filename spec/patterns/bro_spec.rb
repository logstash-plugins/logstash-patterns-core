# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "BRO_HTTP", ['legacy'] do

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
    expect(grok).to include("uid" => "COpk6E3vkURP8QQNKl")
  end

  it "generates the orig_ fields" do
    expect(grok).to include("orig_h" => "192.168.9.35", "orig_p" => "55281")
  end

  it "generates the resp_ fields" do
    expect(grok).to include("resp_h" => "178.236.7.146", "resp_p" => "80")
  end

  it "generates the trans_depth field" do
    expect(grok).to include("trans_depth" => "4")
  end

  it "generates the method field" do
    expect(grok).to include("method" => "POST")
  end

  it "generates the domain field" do
    expect(grok).to include("domain" => "www.amazon.it")
  end

  it "generates the uri field" do
    expect(grok).to include("uri" => "/xa/dealcontent/v2/GetDeals?nocache=1432555199326")
  end

  it "generates the referrer field" do
    expect(grok).to include("referrer" => "http://www.amazon.it/")
  end

  it "generates the user_agent field" do
    expect(grok).to include("user_agent" => "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36")
  end

  it "generates the request_body_len/response_body_len fields" do
    expect(grok).to include("request_body_len" => "223")
    expect(grok).to include("response_body_len" => "1859")
  end

  it "generates the status_ fields" do
    expect(grok).to include("status_code" => "200", "status_msg" => "OK")
  end

  it "generates the info_ fields" do
    expect(grok).to include("info_code" => "-", "info_msg" => "-")
  end

  it "generates the filename field" do
    expect(grok).to include("filename" => "-")
  end

  it "generates the bro_tags field" do
    expect(grok).to include("bro_tags" => "(empty)")
  end

  it "generates the username/password fields" do
    expect(grok).to include("username" => "-")
    expect(grok).to include("password" => "-")
  end

  it "generates the proxied field" do
    expect(grok).to include("proxied" => "-")
  end

  it "generates the orig_ fields" do
    expect(grok).to include("orig_fuids" => "FrLEcY3AUPKdcYGf29")
    expect(grok).to include("orig_mime_types" => "text/plain")
  end

  it "generates the resp_ fields" do
    expect(grok).to include("resp_fuids" => "FOJpbGzIMh9syPxH8")
    expect(grok).to include("resp_mime_types" => "text/plain")
  end

end
