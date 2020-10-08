# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "HTTP" do

  let(:value)   { "1432555199.633017	COpk6E3vkURP8QQNKl	192.168.9.35	55281	178.236.7.146	80	4	POST	www.amazon.it	/xa/dealcontent/v2/GetDeals?nocache=1432555199326	http://www.amazon.it/	Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36	223	1859	200	OK	-	-	-	(empty)	-	-	-	FrLEcY3AUPKdcYGf29	text/plain	FOJpbGzIMh9syPxH8	text/plain" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end
  
  it "generates the ts field" do
    expect(grok).to include("ts" => "1432555199.633017")
  end

  it "generates the uid field" do
    expect(grok).to include("uid" => "COpk6E3vkURP8QQNKl")
  end

  it "generates the orig_h field" do
    expect(grok).to include("orig_h" => "192.168.9.35")
  end

  it "generates the orig_p field" do
    expect(grok).to include("orig_p" => "55281")
  end

  it "generates the resp_h field" do
    expect(grok).to include("resp_h" => "178.236.7.146")
  end

  it "generates the resp_p field" do
    expect(grok).to include("resp_p" => "80")
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

  it "generates the request_body_len field" do
    expect(grok).to include("request_body_len" => "223")
  end

  it "generates the response_body_len field" do
    expect(grok).to include("response_body_len" => "1859")
  end

  it "generates the status_code field" do
    expect(grok).to include("status_code" => "200")
  end

  it "generates the status_msg field" do
    expect(grok).to include("status_msg" => "OK")
  end

  it "generates the info_code field" do
    expect(grok).to include("info_code" => "-")
  end

  it "generates the info_msg field" do
    expect(grok).to include("info_msg" => "-")
  end

  it "generates the filename field" do
    expect(grok).to include("filename" => "-")
  end

  it "generates the bro_tags field" do
    expect(grok).to include("bro_tags" => "(empty)")
  end

  it "generates the username field" do
    expect(grok).to include("username" => "-")
  end

  it "generates the password field" do
    expect(grok).to include("password" => "-")
  end

  it "generates the proxied field" do
    expect(grok).to include("proxied" => "-")
  end

  it "generates the orig_fuids field" do
    expect(grok).to include("orig_fuids" => "FrLEcY3AUPKdcYGf29")
  end

  it "generates the orig_mime_types field" do
    expect(grok).to include("orig_mime_types" => "text/plain")
  end

  it "generates the resp_fuids field" do
    expect(grok).to include("resp_fuids" => "FOJpbGzIMh9syPxH8")
  end

  it "generates the resp_mime_types field" do
    expect(grok).to include("resp_mime_types" => "text/plain")
  end

end
