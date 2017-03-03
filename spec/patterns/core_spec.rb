# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "SYSLOGLINE" do

  let(:value)   { "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]" }
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

describe "URIPROTO" do
  let(:pattern) { 'URIPROTO' }

  context "http is a valid URIPROTO" do
    let(:value) { 'http' }

    it "should match" do
      expect(grok_match(pattern,value)).to pass
    end
  end

  context "android-app is a valid URIPROTO" do
    let(:value) { 'android-app' }

    it "should match" do
      expect(grok_match(pattern,value)).to pass
    end
  end
end

describe "URIPATH" do
  let(:pattern) { 'URIPATH' }

  context "when matching valid URIs" do
    context "and the URI is simple" do
      let(:value) { '/foo' }

      it "should match the path" do
        expect(grok_match(pattern,value)).to pass
      end
    end

    context "and the URI has a trailing slash" do
      let(:value) { '/foo/' }

      it "should match the path" do
        expect(grok_match(pattern,value)).to pass
      end
    end

    context "and the URI has multiple levels" do
      let(:value) { '/foo/bar' }

      it "should match the path" do
        expect(grok_match(pattern,value)).to pass
      end
    end

    context "and the URI has fancy characters" do
      let(:value) { '/aA1$.+!*\'(){},~:;=@#%&|-' }

      it "should match the path" do
        expect(grok_match(pattern,value)).to pass
      end
    end
  end

  context "when matching invalid URIs" do
    context "and the URI has no leading slash" do
      let(:value) { 'foo' }

      it "should not match the path" do
        expect(grok_match(pattern,value)).not_to pass
      end
    end

    context "and the URI has invalid characters" do
      let(:value) { '/`' }

      xit "should not match the path" do
        expect(grok_match(pattern,value)).not_to pass
      end
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

describe "URN" do

  let(:pattern)       { "URN" }

  # Valid URNs
  # http://tools.ietf.org/html/rfc2141#section-2
  let(:simple)        { "urn:example:foo" }
  let(:unreserved)    { "urn:example:" +
    [*'A'..'Z', *'a'..'z', *'0'..'9', "()+,-.::=@;$_!*'"].join() }
  let(:reserved)      { "urn:example:/#?" }
  let(:escaped_upper) { "urn:example:%25foo%2Fbar%3F%23" }
  let(:escaped_lower) { "urn:example:%25foo%2fbar%3f%23" }
  let(:only_escaped)  { "urn:example:%00" }
  let(:long_nid)      { "urn:example-example-example-example-:foo" }

  # Invalid URNs
  let(:bad_prefix)     { "URN:example:foo" }
  let(:empty_nid)      { "urn::foo" }
  let(:leading_hyphen) { "urn:-example:foo" }
  let(:bad_nid)        { "urn:example.com:foo" }
  let(:percent_nid)    { "urn:example%41com:foo" }
  let(:too_long_nid)   { "urn:example-example-example-example-x:foo" }
  let(:empty_nss)      { "urn:example:" }
  let(:naked_percent)  { "urn:example:%" }
  let(:short_percent)  { "urn:example:%a" }
  let(:nonhex_percent) { "urn:example:%ax" }

  context "when testing a valid URN" do
    it "should match a simple URN" do
      expect(grok_match(pattern, simple)).to pass
    end

    it "should match a complex URN" do
      expect(grok_match(pattern, unreserved)).to pass
    end

    it "should allow reserved characters" do
      expect(grok_match(pattern, reserved)).to pass
    end

    it "should allow percent-escapes" do
      expect(grok_match(pattern, escaped_upper)).to pass
      expect(grok_match(pattern, escaped_lower)).to pass
      expect(grok_match(pattern, only_escaped)).to pass
    end

    it "should match a URN with a 32-character NID" do
      expect(grok_match(pattern, long_nid)).to pass
    end
  end

  context "when testing an invalid URN" do
    it "should reject capitalized 'URN'" do
      expect(grok_match(pattern, bad_prefix)).not_to pass
    end

    it "should reject an empty NID" do
      expect(grok_match(pattern, empty_nid)).not_to pass
    end

    it "should reject an NID with a leading hyphen" do
      expect(grok_match(pattern, leading_hyphen)).not_to pass
    end

    it "should reject an NID with a special character" do
      expect(grok_match(pattern, bad_nid)).not_to pass
    end

    it "should reject an NID with a percent sign" do
      expect(grok_match(pattern, percent_nid)).not_to pass
    end

    it "should reject an NID longer than 32 characters" do
      expect(grok_match(pattern, too_long_nid)).not_to pass
    end

    it "should reject a URN with an empty NSS" do
      expect(grok_match(pattern, empty_nss)).not_to pass
    end

    it "should reject non-escape percent signs" do
      expect(grok_match(pattern, naked_percent)).not_to pass
      expect(grok_match(pattern, short_percent)).not_to pass
      expect(grok_match(pattern, nonhex_percent)).not_to pass
    end
  end
end
