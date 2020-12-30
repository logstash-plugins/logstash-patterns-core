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
        expect(subject).to include("timestamp"=>"Dec  9 13:01:26")
        expect(subject).to include("host"=>{"hostname"=>"localhost"})
        expect(subject).to include("process"=>{"pid"=>28029, "name"=>"haproxy"})
        expect(subject).to include("source"=>{"port"=>39759, "address"=>"127.0.0.1", "bytes"=>83285})
        expect(subject).to include("haproxy" => hash_including("request_date"=>"09/Dec/2013:12:59:46.633"))
        expect(subject).to include("haproxy" => hash_including("frontend_name"=>"loadbalancer", "backend_name"=>"default", "server_name"=>"instance8"))
        expect(subject).to include("haproxy" => hash_including(
            "total_waiting_time_ms"=>51536, "connection_wait_time_ms"=>1, "total_time_ms"=>"99627",
            "http" => hash_including("request"=>hash_including("time_wait_ms"=>0, "time_wait_without_data_ms"=>48082))
        ))
        expect(subject).to include("http" => hash_including("response"=>{"status_code"=>200}))

        expect(subject).to include("haproxy" => hash_including("termination_state"=>"----"))

        expect(subject).to include("haproxy" => hash_including("connections"=>{"active"=>87, "frontend"=>87, "backend"=>87, "server"=>1, "retries"=>0}))
        expect(subject).to include("haproxy" => hash_including("backend_queue"=>67, "server_queue"=>0))

        expect(subject).to include("http" => hash_including("request" => {"method"=>'GET'}, "version" => '1.1'))

        expect(subject).to include("url" => { "original"=>"/path/to/image", "path"=>"/path/to/image" })
      else
        expect(subject).to include("syslog_timestamp" => "Dec  9 13:01:26")
        expect(subject).to include("syslog_server" => "localhost")
        expect(subject).to include("http_request" => "/path/to/image", "http_status_code" => "200", "http_verb" => "GET", "http_version" => "1.1")
        expect(subject).to include("program" => "haproxy")
        expect(subject).to include("client_ip" => "127.0.0.1")
        expect(subject).to include("http_verb" => "GET")
        expect(subject).to include("server_name" => "instance8")
      end
    end

    it "has no captured cookies" do
      if ecs_compatibility?
        expect((subject['haproxy']['http']['request'] || {}).keys).to_not include('captured_cookie')
        expect((subject['haproxy']['http']['response'] || {}).keys).to_not include('captured_cookie')
      end
    end

    it "includes header captures" do
      if ecs_compatibility?
        expect((subject['haproxy']['http'])).to include('request' => hash_including('captured_headers' => '77.24.148.74'))
        expect((subject['haproxy']['http']['response'] || {}).keys).to_not include('captured_headers')
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
        expect(subject).to include("timestamp"=>"2015-08-26T02:09:48+02:00")
        expect(subject).to include("host"=>{"hostname"=>"localhost"})
        expect(subject).to include("process"=>{"pid"=>14389, "name"=>"haproxy"})

        expect(subject).to include("haproxy" => hash_including("connections"=>{"active"=>1, "frontend"=>1, "backend"=>0, "server"=>1, "retries"=>0}))
        expect(subject).to include("haproxy" => hash_including("backend_queue"=>0, "server_queue"=>0))

        expect(subject).to include("haproxy" => hash_including("frontend_name"=>"services~"))

        expect(subject).to include("http"=>{"response"=>{"status_code"=>304}, "version"=>"1.1", "request"=>{"method"=>"GET"}})
        expect(subject).to include("url"=>hash_including("path"=>"/component---src-pages-index-js-4b15624544f97cf0bb8f.js"))
      else
        expect(subject).to include("program" => "haproxy")
        expect(subject).to include("client_ip" => "5.196.2.38")
        expect(subject).to include("http_verb" => "GET")
        expect(subject).to include("server_name" => "api")
      end
    end

    it "has no header captures" do
      if ecs_compatibility?
        expect((subject['haproxy']['http']['request'] || {}).keys).to_not include('captured_headers')
        expect((subject['haproxy']['http']['response'] || {}).keys).to_not include('captured_headers')
      end
    end

  end

  context 'log line with both request/response headers' do

    let(:message) do
      'Jul 30 09:03:52 home.host haproxy[32450]: 1.2.3.4:38862 [30/Jul/2018:09:03:52.726] incoming~ docs_microservice/docs 0/0/1/0/2 304 168 - - ---- 6/6/0/0/0 0/0 {docs.example.internal||} {|||} "GET http://192.168.0.12:8080/serv/login.php?lang=en&profile=2 HTTP/1.1"'
    end

    it "matches" do
      if ecs_compatibility?
        expect(subject).to include("timestamp"=>"Jul 30 09:03:52")
        expect(subject).to include("host"=>{"hostname"=>"home.host"})

        expect(subject).to include("haproxy" => hash_including("frontend_name"=>"incoming~"))

        expect(subject).to include("http"=>{"response"=>{"status_code"=>304}, "version"=>"1.1", "request"=>{"method"=>"GET"}})
        expect(subject).to include("url"=>hash_including("scheme"=>"http", "domain"=>"192.168.0.12", "port"=>8080,
                                             "path"=>"/serv/login.php", "query"=>"lang=en&profile=2",
                                             "original"=>"http://192.168.0.12:8080/serv/login.php?lang=en&profile=2"))
      else
        expect(subject).to include("client_ip" => "1.2.3.4")
        expect(subject).to include("http_verb" => "GET")
      end
    end

    it "has header captures" do
      if ecs_compatibility?
        expect((subject['haproxy']['http']['request'])).to include('captured_headers' => 'docs.example.internal||')
        expect((subject['haproxy']['http']['response'])).to include('captured_headers' => '|||')
      end
    end

  end

  context 'BADREQ/NOSRV log line' do

    let(:message) do
      'Jul 18 17:05:30 localhost haproxy[8247]: 188.223.50.7:51940 [18/Jul/2011:17:05:24.339] http_proxy_ads http_proxy_ads/<NOSRV> -1/-1/-1/-1/6001 408 212 - - cR-- 100/89/0/0/0 0/0 "<BADREQ>"'
    end

    it "matches" do
      if ecs_compatibility?
        expect(subject).to include("timestamp"=>"Jul 18 17:05:30")

        expect(subject).to include("haproxy" => hash_including("frontend_name"=>"http_proxy_ads"))
        expect(subject).to include("haproxy" => hash_including("backend_name"=>"http_proxy_ads"))
        expect(subject['haproxy'].keys).to_not include('server_name')
        expect(subject).to include("http"=>{"response"=>{"status_code"=>408}})
        expect(subject['haproxy'].keys).to_not include("total_waiting_time_ms", "connection_wait_time_ms")
        expect(subject).to include("haproxy" => hash_including("total_time_ms"=>"6001"))
        expect(subject).to include("source" => hash_including("bytes"=>212))
        expect(subject).to include("haproxy" => hash_including("termination_state"=>"cR--"))
        expect(subject.keys).to_not include("url")
      else
        expect(subject).to include("backend_name"=>"http_proxy_ads", "frontend_name"=>"http_proxy_ads", "server_name"=>"<NOSRV>")
        expect(subject).to include("http_status_code"=>"408")
        expect(subject).to include("time_backend_connect"=>"-1", "time_queue"=>"-1", "time_backend_response"=>"-1")
        expect(subject).to include("captured_request_cookie"=>"-", "captured_response_cookie"=>"-")
        expect(subject).to include("bytes_read"=>"212")
        expect(subject).to include("termination_state"=>"cR--")
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
        expect(subject).to include("source"=>{"port"=>39759, "address"=>"127.0.0.1", "bytes"=>83285})
        expect(subject).to include("haproxy"=>hash_including("server_queue"=>0,
                                  "http"=>{
                                      "request"=>{"time_wait_ms"=>0, "captured_headers"=>"77.24.148.74", "time_wait_without_data_ms"=>48082}
                                  },

                                  # NOTE: this is why we do not type-cast to :int
                                  # a '+' sign is prepended before the value, indicating that the final one will be larger
                                  "total_time_ms" => "+99627"
        ))
        expect(subject).to include("url"=>{"path"=>"/", "original"=>"/"})
      else
        # Assume 'program' would be matched by the syslog input.
        expect(subject).to include("client_ip" => "127.0.0.1")
        expect(subject).to include("server_name" => "instance8")
        expect(subject).to include("http_verb" => "GET", "http_request"=>"/", "http_version" => '1.1')
        expect(subject).to include("time_duration" => "+99627")
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
        expect(subject).to include("http"=>{"response"=>{"status_code"=>200}, "request"=>{"method"=>"GET"}})
        expect(subject).to include("url"=>hash_including("original"=>"/path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"))
      else
        expect(subject).to include("client_ip" => "203.0.113.54")
        expect(subject).to include("http_verb" => "GET")
        expect(subject).to include("server_name" => "instance8")
        expect(subject).to include("http_request" => "/path/to/request/that/exceeds/more/than/1024/characterssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss")
        expect(subject).to_not have_key("http_version")
      end
    end

  end


  context "connect line with host:port url" do

    let(:message) do
      'Nov  4 08:32:18 debian10 haproxy[3666]: 127.0.0.1:34500 [04/Nov/2020:08:32:18.194] samplefrontend backendnodes/node1 0/0/0/0/0 405 501 - - ---- 1/1/0/1/0 0/0 "CONNECT localhost:8080 HTTP/1.1"'
    end

    it 'matches' do
      if ecs_compatibility?
        expect(subject).to include("http"=>hash_including("request"=>{"method"=>"CONNECT"}))
        expect(subject).to include("url"=>{"port"=>8080, "original"=>"localhost:8080", "domain"=>"localhost"})
      else
        expect(subject).to include("http_verb" => "CONNECT")
        expect(subject).to include("http_host" => "localhost:8080")
      end
    end

  end

end

describe_pattern "HAPROXYTCP", ['legacy', 'ecs-v1'] do

  let(:message) do
    'Sep 20 15:44:23 127.0.0.1 haproxy[25457]: 127.0.0.1:40962 [20/Sep/2018:15:44:23.285] main app/<NOSRV> -1/-1/1 212 SC 1/1/0/0/0 0/0'
  end

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include(
                            "timestamp"=>"Sep 20 15:44:23",
                            "host"=>{"hostname"=>"127.0.0.1"},
                            "process"=>{"pid"=>25457, "name"=>"haproxy"},
                            "source"=>{"port"=>40962, "address"=>"127.0.0.1", "bytes"=>212},
                            "haproxy"=>{
                                "request_date"=>"20/Sep/2018:15:44:23.285",
                                "frontend_name"=>"main", "backend_name"=>"app",
                                "total_time_ms"=>"1",
                                "termination_state"=>"SC",
                                "connections"=>{"active"=>1, "backend"=>0, "retries"=>0, "server"=>0, "frontend"=>1},
                                "server_queue"=>0, "backend_queue"=>0
                            })
    else
      expect(subject).to include(
                            "syslog_timestamp"=>"Sep 20 15:44:23",
                            "syslog_server"=>"127.0.0.1",
                            "program"=>"haproxy", "pid"=>"25457",
                            "client_ip"=>"127.0.0.1", "client_port"=>"40962",
                            "accept_date"=>"20/Sep/2018:15:44:23.285",
                            "frontend_name"=>"main",
                            "backend_name"=>"app",
                            "server_name"=>"<NOSRV>",
                            "time_backend_connect"=>"-1",
                            "time_queue"=>"-1",
                            "time_duration"=>"1",
                            "bytes_read"=>"212",
                            "termination_state"=>"SC",
                            "actconn"=>"1", "feconn"=>"1", "beconn"=>"0", "backend_queue"=>"0", "retries"=>"0",
                            "srv_queue"=>"0", "srvconn"=>"0",
                            )
    end
  end

end