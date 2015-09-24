# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "SYSLOGLINE" do

  let(:value)   { "Mar 16 00:01:25 UNKNOWN_HOSTNAME postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]" }
  let(:grok)    { grok_match(subject, value) }
  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the program field" do
    expect(grok_match(subject, value)).to include("program" => "postfix/smtpd")
  end

  it "generates the host field" do
    expect(grok_match(subject, value)).to include("logsource" => "UNKNOWN_HOSTNAME")
  end
end

describe "COMMONAPACHELOG" do

  let(:value) { '83.149.9.216 - - [24/Feb/2015:23:13:42 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36'}

  it "generates the clientip field" do
    expect(grok_match(subject, value)).to include("clientip" => "83.149.9.216")
  end

end

describe "HTTP DATE parsing" do

  context "HTTPDATE", "when having a German month" do

    let(:value) { '[04/Mai/2015:13:17:15 +0200]'}

    it "generates the month field" do
      expect(grok_match(subject, value)).to pass
    end

  end

  context "HTTPDATE", "when having a English month" do

    let(:value) { '[04/March/2015:13:17:15 +0200]'}

    it "generates the month field" do
      expect(grok_match(subject, value)).to pass
    end

  end

  context "HTTPDATE", "when having a wrong months" do

    let(:value) { '[04/Map/2015:13:17:15 +0200]'}

    it "generates the month field" do
      expect(grok_match(subject, value)).not_to pass
    end

  end

end

describe "TOMCATLOG" do

  let(:value) { '2014-01-09 20:03:28,269 -0800 | ERROR | com.example.service.ExampleService - something compeletely unexpected happened...'}

  it "generates the logmessage field" do
    expect(grok_match(subject, value)).to include("logmessage" => "something compeletely unexpected happened...")
  end
end

describe "IPORHOST" do

  let(:pattern)    { "IPORHOST" }

  context "matching an IP" do
    let(:value) { '127.0.0.1' }

    it "should match the IP value" do
      expect(grok_match(pattern, value)).to pass
    end
  end

  context "matching a HOST" do
    let(:value) { 'example.org' }

    it "should match the IP value" do
      expect(grok_match(pattern, value)).to pass
    end
  end
end

describe "UNIXPATH" do

  let(:pattern) { 'UNIXPATH' }
  let(:value)   { '/foo/bar' }

  it "should match the path" do
    expect(grok_match(pattern,value)).to pass
  end

  context "when using comma separators and other regexp" do

    let(:value) { 'a=/some/path, b=/some/other/path' }

    it "should match the path" do
      expect(grok_match(pattern,value)).to pass
    end
  end
end

describe "IPV4" do

  let(:pattern) { 'IPV4' }
  let(:value) { "127.0.0.1" }

  it "should match the path" do
    expect(grok_match(pattern,value)).to pass
  end

  context "when parsing a local IP" do
    let(:value) { "10.0.0.1" }

    it "should match the path" do
      expect(grok_match(pattern,value)).to pass
    end
  end

  context "when parsing a wrong IP" do
    let(:value) { "192.300.300.300" }

    it "should match the path" do
      expect(grok_match(pattern,value)).not_to pass
    end
  end

end
