# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "HAPROXY" do

  let(:haproxyhttp_pattern)  { "HAPROXYHTTP" }

  context "Parsing HAPROXY log line from raw syslog line" do

    let(:value) { 'Dec  9 13:01:26 localhost haproxy[28029]: 127.0.0.1:39759 [09/Dec/2013:12:59:46.633] loadbalancer default/instance8 0/51536/1/48082/99627 200 83285 - - ---- 87/87/87/1/0 0/67 {77.24.148.74} "GET /path/to/image HTTP/1.1"' }
    subject     { grok_match(haproxyhttp_pattern, value) }

    it { should include("program" => "haproxy") }
    it { should include("client_ip" => "127.0.0.1") }
    it { should include("http_verb" => "GET") }
    it { should include("server_name" => "instance8") }

    it "generates a message field" do
      expect(subject["message"]).to include("loadbalancer default/instance8")
    end

  end

  context "Parsing HAPROXY log line from raw syslog line with ISO8601 timestamp" do

    let(:value) { '2015-08-26T02:09:48+02:00 localhost haproxy[28029]: 127.0.0.1:39759 [09/Dec/2013:12:59:46.633] loadbalancer default/instance8 0/51536/1/48082/99627 200 83285 - - ---- 87/87/87/1/0 0/67 {77.24.148.74} "GET /path/to/image HTTP/1.1"' }
    subject     { grok_match(haproxyhttp_pattern, value) }

    it { should include("program" => "haproxy") }
    it { should include("client_ip" => "127.0.0.1") }
    it { should include("http_verb" => "GET") }
    it { should include("server_name" => "instance8") }

    it "generates a message field" do
      expect(subject["message"]).to include("loadbalancer default/instance8")
    end

  end

  let(:haproxyhttpbase_pattern)  { "HAPROXYHTTPBASE" }

  context "Parsing HAPROXY log line without syslog specific enteries.  This mimics an event coming from a syslog input." do

    let(:value) { '127.0.0.1:39759 [09/Dec/2013:12:59:46.633] loadbalancer default/instance8 0/51536/1/48082/99627 200 83285 - - ---- 87/87/87/1/0 0/67 {77.24.148.74} "GET /path/to/image HTTP/1.1"' }
    subject     { grok_match(haproxyhttpbase_pattern, value) }

    # Assume 'program' would be matched by the syslog input.
    it { should include("client_ip" => "127.0.0.1") }
    it { should include("http_verb" => "GET") }
    it { should include("server_name" => "instance8") }

    it "generates a message field" do
      expect(subject["message"]).to include("loadbalancer default/instance8")
    end

  end

  context "Parsing HAPROXY log line that is truncated and thus not ending with a double quote or HTTP version." do

    let(:value) { 'Jul 31 22:20:22 loadbalancer haproxy[1190]: 203.0.113.54:59968 [31/Jul/2017:22:20:22.447] loadbalancer default/instance8 135/0/1/19/156 200 1015 - - --VR 8/8/0/0/0 0/0 "GET /path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss'}
    subject     { grok_match(haproxyhttpbase_pattern, value)}

    it { should include("client_ip" => "203.0.113.54") }
    it { should include("http_verb" => "GET") }
    it { should include("server_name" => "instance8") }
    it { should include("http_request" => "/path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss") }
    it { should_not have_key("http_version") }

    it "generates a message field" do
      expect(subject["message"]).to include("loadbalancer default/instance8")
    end

  end

end
