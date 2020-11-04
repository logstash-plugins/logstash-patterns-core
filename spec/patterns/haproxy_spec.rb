# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "HAPROXYHTTP", ['legacy', 'ecs-v1'] do

  context "log line from raw syslog line" do

    let(:message) do
      'Dec  9 13:01:26 localhost haproxy[28029]: 127.0.0.1:39759 [09/Dec/2013:12:59:46.633] loadbalancer default/instance8 0/51536/1/48082/99627 200 83285 - - ---- 87/87/87/1/0 0/67 {77.24.148.74} "GET /path/to/image HTTP/1.1"'
    end

    it "matches" do
      if ecs_compatibility?
        should include("timestamp"=>"Dec  9 13:01:26")
        should include("host"=>{"hostname"=>"localhost"})
        should include("process"=>{"pid"=>28029, "name"=>"haproxy"})
        should include("source"=>{"port"=>39759, "address"=>"127.0.0.1"})
        should include("haproxy" => hash_including("request_date"=>"09/Dec/2013:12:59:46.633"))
        should include("haproxy" => hash_including("frontend_name"=>"loadbalancer", "backend_name"=>"default", "server_name"=>"instance8"))
        should include("haproxy" => hash_including(
            "total_waiting_time_ms"=>51536, "connection_wait_time_ms"=>1, "total_time_ms"=>"99627",
            "http" => hash_including("request"=>hash_including("time_wait_ms"=>0, "time_wait_without_data_ms"=>48082))
        ))
        should include("http" => hash_including("response"=>{"status_code"=>200}))
        should include("haproxy" => hash_including("bytes_read"=>83285))

        should include("haproxy" => hash_including("termination_state"=>"----"))

        should include("haproxy" => hash_including("connections"=>{"active"=>87, "frontend"=>87, "backend"=>87, "server"=>1, "retries"=>0}))
        should include("haproxy" => hash_including("backend_queue"=>67, "server_queue"=>0))

        should include("http" => hash_including("request" => {"method"=>'GET'}, "version" => '1.1'))

        should include("url" => { "original"=>"/path/to/image", "path"=>"/path/to/image" })
      else
        should include("syslog_timestamp" => "Dec  9 13:01:26")
        should include("syslog_server" => "localhost")
        should include("http_request" => "/path/to/image", "http_status_code" => "200", "http_verb" => "GET", "http_version" => "1.1")
        should include("program" => "haproxy")
        should include("client_ip" => "127.0.0.1")
        should include("http_verb" => "GET")
        should include("server_name" => "instance8")
      end
    end

    it "has no captured cookies" do
      if ecs_compatibility?
        expect((grok['haproxy']['http']['request'] || {}).keys).to_not include('captured_cookie')
        expect((grok['haproxy']['http']['response'] || {}).keys).to_not include('captured_cookie')
      end
    end

    it "includes header captures" do
      if ecs_compatibility?
        expect((grok['haproxy']['http'])).to include('request' => hash_including('captured_headers' => '77.24.148.74'))
        expect((grok['haproxy']['http']['response'] || {}).keys).to_not include('captured_headers')
      end
    end

    it "generates a message field" do
      expect(subject["message"]).to include("loadbalancer default/instance8")
    end

  end

  context "log line (without headers) from raw syslog line with ISO8601 timestamp" do

    let(:message) do
      '2015-08-26T02:09:48+02:00 localhost haproxy[14389]: 5.196.2.38:39527 [03/Nov/2015:06:25:25.105] services~ def/api 4599/0/0/428/5027 304 320 - - ---- 1/1/0/1/0 0/0 "GET /component---src-pages-index-js-4b15624544f97cf0bb8f.js HTTP/1.1"'
    end

    it "matches" do
      if ecs_compatibility?
        should include("timestamp"=>"2015-08-26T02:09:48+02:00")
        should include("host"=>{"hostname"=>"localhost"})
        should include("process"=>{"pid"=>14389, "name"=>"haproxy"})

        should include("haproxy" => hash_including("connections"=>{"active"=>1, "frontend"=>1, "backend"=>0, "server"=>1, "retries"=>0}))
        should include("haproxy" => hash_including("backend_queue"=>0, "server_queue"=>0))

        should include("haproxy" => hash_including("frontend_name"=>"services~"))

        should include("http"=>{"response"=>{"status_code"=>304}, "version"=>"1.1", "request"=>{"method"=>"GET"}})
        should include("url"=>hash_including("path"=>"/component---src-pages-index-js-4b15624544f97cf0bb8f.js"))
      else
        should include("program" => "haproxy")
        should include("client_ip" => "5.196.2.38")
        should include("http_verb" => "GET")
        should include("server_name" => "api")
      end
    end

    it "has no header captures" do
      if ecs_compatibility?
        expect((grok['haproxy']['http']['request'] || {}).keys).to_not include('captured_headers')
        expect((grok['haproxy']['http']['response'] || {}).keys).to_not include('captured_headers')
      end
    end

  end

  context 'log line with both request/response headers' do

    let(:message) do
      'Jul 30 09:03:52 home.host haproxy[32450]: 1.2.3.4:38862 [30/Jul/2018:09:03:52.726] incoming~ docs_microservice/docs 0/0/1/0/2 304 168 - - ---- 6/6/0/0/0 0/0 {docs.example.internal||} {|||} "GET http://192.168.0.12:8080/serv/login.php?lang=en&profile=2 HTTP/1.1"'
    end

    it "matches" do
      if ecs_compatibility?
        should include("timestamp"=>"Jul 30 09:03:52")
        should include("host"=>{"hostname"=>"home.host"})

        should include("haproxy" => hash_including("frontend_name"=>"incoming~"))

        should include("http"=>{"response"=>{"status_code"=>304}, "version"=>"1.1", "request"=>{"method"=>"GET"}})
        should include("url"=>hash_including("scheme"=>"http", "domain"=>"192.168.0.12", "port"=>8080,
                                             "path"=>"/serv/login.php", "query"=>"lang=en&profile=2",
                                             "original"=>"http://192.168.0.12:8080/serv/login.php?lang=en&profile=2"))
      else
        should include("client_ip" => "1.2.3.4")
        should include("http_verb" => "GET")
      end
    end

    it "has header captures" do
      if ecs_compatibility?
        expect((grok['haproxy']['http']['request'])).to include('captured_headers' => 'docs.example.internal||')
        expect((grok['haproxy']['http']['response'])).to include('captured_headers' => '|||')
      end
    end

  end

  context 'BADREQ/NOSRV log line' do

    let(:message) do
      'Jul 18 17:05:30 localhost haproxy[8247]: 188.223.50.7:51940 [18/Jul/2011:17:05:24.339] http_proxy_ads http_proxy_ads/<NOSRV> -1/-1/-1/-1/6001 408 212 - - cR-- 100/89/0/0/0 0/0 "<BADREQ>"'
    end

    it "matches" do
      if ecs_compatibility?
        should include("timestamp"=>"Jul 18 17:05:30")

        should include("haproxy" => hash_including("frontend_name"=>"http_proxy_ads"))
        should include("haproxy" => hash_including("backend_name"=>"http_proxy_ads"))
        expect( grok['haproxy'].keys ).to_not include('server_name')
        should include("http"=>{"response"=>{"status_code"=>408}})
        expect( grok['haproxy'].keys ).to_not include("total_waiting_time_ms", "connection_wait_time_ms")
        should include("haproxy" => hash_including("total_time_ms"=>"6001"))
        should include("haproxy" => hash_including("bytes_read"=>212))
        should include("haproxy" => hash_including("termination_state"=>"cR--"))
        expect( grok.keys ).to_not include("url")
      else
        should include("backend_name"=>"http_proxy_ads", "frontend_name"=>"http_proxy_ads", "server_name"=>"<NOSRV>")
        should include("http_status_code"=>"408")
        should include("time_backend_connect"=>"-1", "time_queue"=>"-1", "time_backend_response"=>"-1")
        should include("captured_request_cookie"=>"-", "captured_response_cookie"=>"-")
        should include("bytes_read"=>"212")
        should include("termination_state"=>"cR--")
      end
    end

  end

end

describe_pattern "HAPROXYHTTPBASE", ['ecs-v1', 'legacy'] do

  context "log line without syslog specific entries" do # This mimics an event coming from a syslog input.

    let(:message) do
      '127.0.0.1:39759 [09/Dec/2013:12:59:46.633] loadbalancer default/instance8 0/51536/1/48082/+99627 200 83285 - - ---- 87/87/87/1/0 0/67 {77.24.148.74} "GET / HTTP/1.1"'
    end

    it 'matches' do
      if ecs_compatibility?
        should include("source"=>{"port"=>39759, "address"=>"127.0.0.1"})
        should include("haproxy"=>hash_including("server_queue"=>0,
                                  "http"=>{
                                      "request"=>{"time_wait_ms"=>0, "captured_headers"=>"77.24.148.74", "time_wait_without_data_ms"=>48082}
                                  },

                                  # NOTE: this is why we do not type-cast to :int
                                  # a '+' sign is prepended before the value, indicating that the final one will be larger
                                  "total_time_ms" => "+99627"
        ))
        should include("url"=>{"path"=>"/", "original"=>"/"})
      else
        # Assume 'program' would be matched by the syslog input.
        should include("client_ip" => "127.0.0.1")
        should include("server_name" => "instance8")
        should include("http_verb" => "GET", "http_request"=>"/", "http_version" => '1.1')
        should include("time_duration" => "+99627")
      end
    end

  end

  context "(incomplete) log line that is truncated and thus not ending with a double quote or HTTP version" do

    let(:message) do
      'Jul 31 22:20:22 loadbalancer haproxy[1190]: 203.0.113.54:59968 [31/Jul/2017:22:20:22.447] loadbalancer default/instance8 135/0/1/19/156 200 1015 - - --VR 8/8/0/0/0 0/0 "GET /path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss'
    end

    it 'matches' do
      if ecs_compatibility?
        # due compatibility with the legacy pattern we match the incomplete "REQUEST LINE ... (wout the ending '"')
        should include("http"=>{"response"=>{"status_code"=>200}, "request"=>{"method"=>"GET"}})
        should include("url"=>hash_including("original"=>"/path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"))
      else
        should include("client_ip" => "203.0.113.54")
        should include("http_verb" => "GET")
        should include("server_name" => "instance8")
        should include("http_request" => "/path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss")
        should_not have_key("http_version")
      end
    end

  end


  context "connect line with host:port url" do

    let(:message) do
      'Nov  4 08:32:18 debian10 haproxy[3666]: 127.0.0.1:34500 [04/Nov/2020:08:32:18.194] samplefrontend backendnodes/node1 0/0/0/0/0 405 501 - - ---- 1/1/0/1/0 0/0 "CONNECT localhost:8080 HTTP/1.1"'
    end

    it 'matches' do
      if ecs_compatibility?
        should include("http"=>hash_including("request"=>{"method"=>"CONNECT"}))
        should include("url"=>{"port"=>8080, "original"=>"localhost:8080", "domain"=>"localhost"})
      else
        should include("http_verb" => "CONNECT")
        should include("http_host" => "localhost:8080")
      end
    end

  end

end
