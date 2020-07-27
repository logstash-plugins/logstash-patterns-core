# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "SQUID3" do

  let(:grok) { grok_match("SQUID3", value) }

  describe 'CONNECT sample' do

    let(:value) do
      '1525344856.899  16867 10.170.72.111 TCP_TUNNEL/200 6256 CONNECT logs.ap-southeast-2.amazonaws.com:443 - HIER_DIRECT/53.140.206.134 -'
    end

    it "matches" do
      expect(grok).to include(
                          "timestamp" => "1525344856.899",
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

  describe 'GET sample' do

    let(:value) do
      "1525334330.556      3 120.65.1.1 TCP_REFRESH_MISS/200 2014 GET http://www.sample.com/hellow_world.txt public-user DIRECT/www.sample.com text/plain 902351708.872"
    end

    it "matches" do
      expect(grok).to include(
                          "timestamp"=>"1525334330.556",
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

    it "retains message" do
      expect(grok).to include("message" => value)
    end

  end

end
