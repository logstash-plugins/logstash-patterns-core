# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"


describe "ELB_ACCESS_LOG" do

  let(:pattern) { "ELB_ACCESS_LOG" }

  context "parsing an access log" do

    let(:value) { "2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 \"GET http://www.example.com:80/ HTTP/1.1\"" }

    subject { grok_match(pattern, value) }

    it { should include("timestamp" => "2014-02-15T23:39:43.945958Z" ) }
    it { should include("elb" => "my-test-loadbalancer" ) }
    it { should include("clientip" => "192.168.131.39" ) }
    it { should include("clientport" => 2817 ) }
    it { should include("backendip" => "10.0.0.1" ) }
    it { should include("backendport" => 80 ) }
    it { should include("request_processing_time" => 0.000073 ) }
    it { should include("backend_processing_time" => 0.001048 ) }
    it { should include("response_processing_time" => 0.000057 ) }
    it { should include("response" => 200 ) }
    it { should include("backend_response" => 200 ) }
    it { should include("received_bytes" => 0 ) }
    it { should include("bytes" => 29 ) }
    it { should include("verb" => "GET" ) }
    it { should include("request" => "http://www.example.com:80/" ) }
    it { should include("proto" => "http" ) }
    it { should include("httpversion" => "1.1" ) }
    it { should include("urihost" => "www.example.com:80" ) }
    it { should include("path" => "/" ) }

    ["tags", "params"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil
      end
    end
  end

  context "parsing a PUT request access log with missing backend info" do

    let(:value) { '2015-04-10T08:11:09.865823Z us-west-1-production-media 49.150.87.133:55128 - -1 -1 -1 408 0 1294336 0 "PUT https://media.xxxyyyzzz.com:443/videos/F4_M-T4X0MM6Hvy1PFHesw HTTP/1.1"' }

    subject { grok_match(pattern, value) }

    it "a pattern pass the grok expression" do
      expect(subject).to pass
    end

    ["backendip", "backendport"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil
      end
    end
  end
end

describe "S3_ACCESS_LOG" do

  let(:pattern)    { "S3_ACCESS_LOG" }

  context "parsing GET.VERSIONING message" do

    let(:value) { "79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - \"GET /mybucket?versioning HTTP/1.1\" 200 - 113 - 7 - \"-\" \"S3Console/0.4\" -" }

    subject { grok_match(pattern, value) }

    it { should include("owner" => "79a5" ) }
    it { should include("bucket" => "mybucket" ) }
    it { should include("timestamp" => "06/Feb/2014:00:00:38 +0000" ) }
    it { should include("clientip" => "192.0.2.3" ) }
    it { should include("requester" => "79a5" ) }
    it { should include("request_id" => "3E57427F3EXAMPLE" ) }
    it { should include("operation" => "REST.GET.VERSIONING" ) }
    it { should include("key" => "-" ) }

    it { should include("verb" => "GET" ) }
    it { should include("request" => "/mybucket?versioning" ) }
    it { should include("httpversion" => "1.1" ) }
    it { should include("response" => 200 ) }
    it { should include("bytes" => 113 ) }

    it { should include("request_time_ms" => 7 ) }
    it { should include("referrer" => "\"-\"" ) }
    it { should include("agent" => "\"S3Console/0.4\"" ) }


    ["tags", "error_code", "object_size", "turnaround_time_ms", "version_id"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil
      end
    end

  end

  context "parsing a GET.OBJECT message" do

    let(:value) { "79a5 mybucket [12/May/2014:07:54:01 +0000] 10.0.1.2 - 7ACC4BE89EXAMPLE REST.GET.OBJECT foo/bar.html \"GET /foo/bar.html HTTP/1.1\" 304 - - 1718 10 - \"-\" \"Mozilla/5.0\" -" }

    subject { grok_match(pattern, value) }

    it { should include("owner" => "79a5" ) }
    it { should include("bucket" => "mybucket" ) }
    it { should include("timestamp" => "12/May/2014:07:54:01 +0000" ) }
    it { should include("clientip" => "10.0.1.2" ) }
    it { should include("requester" => "-" ) }
    it { should include("request_id" => "7ACC4BE89EXAMPLE" ) }
    it { should include("operation" => "REST.GET.OBJECT" ) }
    it { should include("key" => "foo/bar.html" ) }

    it { should include("verb" => "GET" ) }
    it { should include("request" => "/foo/bar.html" ) }
    it { should include("httpversion" => "1.1" ) }
    it { should include("response" => 304 ) }
    it { should include("object_size" => 1718 ) }

    it { should include("request_time_ms" => 10 ) }
    it { should include("referrer" => "\"-\"" ) }
    it { should include("agent" => "\"Mozilla/5.0\"" ) }


    ["tags", "error_code", "turnaround_time_ms", "version_id", "bytes"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil
      end
    end

  end
end

describe "CLOUDFRONT_ACCESS_LOG" do

  let(:pattern) { "CLOUDFRONT_ACCESS_LOG" }

  context "parsing a cloudfront access log" do

    let(:value) { "2016-06-10	18:41:39	IAD53	224281	192.168.1.1	GET	d27enomp470abc.cloudfront.net	/content/sample/thing.pdf	200	https://example.com/	Mozilla/5.0%2520(Windows%2520NT%25206.1;%2520WOW64)%2520AppleWebKit/537.36%2520(KHTML,%2520like%2520Gecko)%2520Chrome/51.0.2704.79%2520Safari/537.36	-	-	Miss	UGskZ6dUKY7b4C6Pt7wAWVsU2KO-vTRe-mR4r9H-WQMjhNvY6w1Xcg==	host.example.com	https	883	0.036	-	TLSv1.2	ECDHE-RSA-AES128-GCM-SHA256	Miss" }

    subject { grok_match(pattern, value) }

    it { should include("timestamp" => "2016-06-10	18:41:39" ) }
    it { should include("x_edge_location" => "IAD53" ) }
    it { should include("sc_bytes" => 224281 ) }
    it { should include("clientip" => "192.168.1.1" ) }
    it { should include("cs_method" =>  "GET" ) }
    it { should include("cs_host" => "d27enomp470abc.cloudfront.net" ) }
    it { should include("cs_uri_stem" => "/content/sample/thing.pdf" ) }
    it { should include("sc_status" => 200 ) }
    it { should include("referrer" => "https://example.com/" ) }
    it { should include("agent" => "Mozilla/5.0%2520(Windows%2520NT%25206.1;%2520WOW64)%2520AppleWebKit/537.36%2520(KHTML,%2520like%2520Gecko)%2520Chrome/51.0.2704.79%2520Safari/537.36" ) }
    it { should include("cs_uri_query" => "-" ) }
    it { should include("cookies" => "-" ) }
    it { should include("x_edge_result_type" => "Miss" ) }
    it { should include("x_edge_request_id" => "UGskZ6dUKY7b4C6Pt7wAWVsU2KO-vTRe-mR4r9H-WQMjhNvY6w1Xcg==" ) }
    it { should include("x_host_header" => "host.example.com" ) }
    it { should include("cs_protocol" => "https" ) }
    it { should include("cs_bytes" => 883 ) }
    it { should include("time_taken" => 0.036 ) }
    it { should include("x_forwarded_for" => "-" ) }
    it { should include("ssl_protocol" => "TLSv1.2" ) }
    it { should include("ssl_cipher" => "ECDHE-RSA-AES128-GCM-SHA256" ) }
    it { should include("x_edge_response_result_type" => "Miss" ) }

    ["tags", "params"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil
      end
    end
  end
end
