# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "SQUID3", ['legacy', 'ecs-v1'] do

  describe 'CONNECT sample' do

    let(:message) do
      '1525344856.899  16867 10.170.72.111 TCP_TUNNEL/200 6256 CONNECT logs.ap-southeast-2.amazonaws.com:443 - HIER_DIRECT/53.140.206.134 -'
    end

    it "matches" do
      expect(grok).to include("timestamp" => "1525344856.899")
      if ecs_compatibility?
        expect(grok).to include(
                            "event" => { "action" => "TCP_TUNNEL" },
                            "squid" => {
                                "request" => { "duration" => 16867 },
                                "response" => { "content_type" => "-" },
                                "hierarchy_code" => "HIER_DIRECT"
                            })
        expect(grok).to include("destination" => { "address" => "53.140.206.134" })
        expect(grok).to include("http" => { "request" => { "method" => "CONNECT" }, "response" => { "bytes" => 6256, "status_code" => 200 } })
        expect(grok).to include("url" => { "original" => "logs.ap-southeast-2.amazonaws.com:443" })
        expect(grok).to include("source" => { "ip" => "10.170.72.111" })
      else
        expect(grok).to include(
                            "duration" => "16867",
                            "client_address" => "10.170.72.111",
                            "cache_result" => "TCP_TUNNEL",
                            "status_code" => "200",
                            "request_method" => "CONNECT",
                            "bytes" => "6256",
                            "url" => "logs.ap-southeast-2.amazonaws.com:443",
                            "user" => "-",
                            "hierarchy_code" => "HIER_DIRECT",
                            "server" => "53.140.206.134",
                            "content_type" => "-",
                            )
      end
    end

  end

  describe 'GET sample' do

    let(:message) do
      "1525334330.556      3 120.65.1.1 TCP_REFRESH_MISS/200 2014 GET http://www.sample.com/hellow_world.txt public-user DIRECT/www.sample.com text/plain 902351708.872"
    end

    it "matches" do
      expect(grok).to include("timestamp" => "1525334330.556")
      if ecs_compatibility?
        expect(grok).to include(
                            "event" => { "action" => "TCP_REFRESH_MISS" },
                            "squid" => {
                                "request" => { "duration" => 3 },
                                "response" => { "content_type" => "text/plain" },
                                "hierarchy_code" => "DIRECT"
                            })
        expect(grok).to include("destination" => { "address" => "www.sample.com" })
        expect(grok).to include("http" => { "request" => { "method" => "GET" }, "response" => { "bytes" => 2014, "status_code" => 200 } })
        expect(grok).to include("url" => { "original" => "http://www.sample.com/hellow_world.txt" })
        expect(grok).to include("source" => { "ip" => "120.65.1.1" })
        expect(grok).to include("user" => { "name" => "public-user" })
      else
        expect(grok).to include(
                            "duration"=>"3",
                            "client_address"=>"120.65.1.1",
                            "cache_result"=>"TCP_REFRESH_MISS",
                            "status_code"=>"200",
                            "bytes"=>"2014",
                            "request_method" => "GET",
                            "url" => "http://www.sample.com/hellow_world.txt",
                            "user"=>"public-user",
                            "hierarchy_code"=>"DIRECT",
                            "server"=>"www.sample.com",
                            "content_type"=>"text/plain",
                            )
      end
    end

    it "retains message" do
      expect(grok).to include("message" => message)
    end

  end

end
