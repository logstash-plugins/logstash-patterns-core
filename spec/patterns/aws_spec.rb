# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "ELB_ACCESS_LOG", ['legacy', 'ecs-v1'] do

  context "parsing an access log" do

    let(:message) do
      "2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 \"GET http://www.example.com:80/ HTTP/1.1\""
    end

    it 'matches' do
      should include("timestamp" => "2014-02-15T23:39:43.945958Z" )
      if ecs_compatibility?
        expect(grok).to include("aws" => { "elb" => {
            "name"=>"my-test-loadbalancer",
            "request_processing_time"=>{"sec"=>0.000073},
            "response_processing_time"=>{"sec"=>0.000057},
            "backend_processing_time"=>{"sec"=>0.001048},
            "backend"=>{
                "ip"=>"10.0.0.1", "port"=>80,
                "http"=>{"response"=>{"status_code"=>200}}
            }
        }})
        expect(grok).to include("http"=>{
            "request"=>{"body"=>{"bytes"=>0}, "method"=>"GET"},
            "response"=>{"body"=>{"bytes"=>29}, "status_code"=>200},
            "version"=>"1.1"
        })
        expect(grok).to include("source"=>{"ip"=>"192.168.131.39", "port"=>2817})
        expect(grok).to include("url"=>{
            "original"=>"http://www.example.com:80/",
            "port"=>80, "path"=>"/", "domain"=>"www.example.com", "scheme"=>"http"
        })
      else
        should include("elb" => "my-test-loadbalancer" )
        should include("clientip" => "192.168.131.39" )
        should include("clientport" => 2817 )
        should include("backendip" => "10.0.0.1" )
        should include("backendport" => 80 )
        should include("request_processing_time" => 0.000073 )
        should include("backend_processing_time" => 0.001048 )
        should include("response_processing_time" => 0.000057 )
        should include("response" => 200 )
        should include("backend_response" => 200 )
        should include("received_bytes" => 0 )
        should include("bytes" => 29 )
        should include("verb" => "GET" )
        should include("request" => "http://www.example.com:80/" )
        should include("proto" => "http" )
        should include("httpversion" => "1.1" )
        should include("urihost" => "www.example.com:80" )
        should include("path" => "/" )
      end
    end

    ["tags", "params"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil
      end
    end
  end

  context "parsing a PUT request access log with missing backend info" do

    let(:message) do
      '2015-04-10T08:11:09.865823Z us-west-1-production-media 49.150.87.133:55128 - -1 -1 -1 408 - 1294336 0 "PUT https://media.xxxyyyzzz.com:443/videos/F4_M-T4X0MM6Hvy1PFHesw HTTP/1.1"'
    end

    it "matches" do
      expect(grok).to include("timestamp"=>"2015-04-10T08:11:09.865823Z")
      if ecs_compatibility?
        expect(grok).to include("url"=>{
            "original"=>"https://media.xxxyyyzzz.com:443/videos/F4_M-T4X0MM6Hvy1PFHesw",
            "scheme"=>"https", "port"=>443, "path"=>"/videos/F4_M-T4X0MM6Hvy1PFHesw", "domain"=>"media.xxxyyyzzz.com"
        })
        expect(grok).to include("source"=>{"port"=>55128, "ip"=>"49.150.87.133"})
        expect(grok).to include("http"=>{
            "request"=>{"method"=>"PUT", "body"=>{"bytes"=>1294336}}, "version"=>"1.1",
            "response"=>{"body"=>{"bytes"=>0}, "status_code"=>408}
        })
        # no backend.ip and backend.port
        # no backend.http.status.code
        # no request_processing_time.sec and friends
        expect(grok).to include("aws"=>{"elb"=>{"name"=>"us-west-1-production-media"}})
      else
        expect(grok).to include(
            "elb"=>"us-west-1-production-media",
            "clientip"=>"49.150.87.133", "clientport"=>55128,
            "response_processing_time"=>-1.0,
            "request_processing_time"=>-1.0,
            "backend_processing_time"=>-1.0,
            "response"=>408,
            "received_bytes"=>1294336,
            "bytes"=>0,
            "verb"=>"PUT",
            "request"=>"https://media.xxxyyyzzz.com:443/videos/F4_M-T4X0MM6Hvy1PFHesw",
            "port"=>"443", "proto"=>"https", "path"=>"/videos/F4_M-T4X0MM6Hvy1PFHesw", "urihost"=>"media.xxxyyyzzz.com:443",
            "httpversion"=>"1.1")

        expect(grok.keys).to_not include("backendip", "backendport", "backendresponse")
      end
    end

  end

  context '(new) https format' do # slightly longer - 3 fields added at the end

    let(:message) do
      '2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "curl/7.38.0 (#56-0ef1d4a5)" DHE-RSA-AES128-SHA TLSv1.2'
    end

    it 'matches (new) suffix fields' do
      if ecs_compatibility?
        expect(grok).to include "tls" => { "cipher" => "DHE-RSA-AES128-SHA" }
        expect(grok).to include "aws" => { "elb" => hash_including("ssl_protocol" => 'TLSv1.2')}
        expect(grok).to include "user_agent"=>{"original"=>"curl/7.38.0 (#56-0ef1d4a5)"}
      end
    end

    context 'with optional fields' do

      let(:message) do
        '2015-05-13T23:39:43.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000086 0.001048 0.001337 200 200 0 57 "GET https://www.example.com:443/ HTTP/1.1" "-" - -'
      end

      it 'matches (new) suffix fields' do
        if ecs_compatibility?
          expect(grok.keys).to_not include "tls"
          expect(grok['aws']['elb'].keys).to_not include "ssl_protocol"
          expect(grok.keys).to_not include "user_agent"
        end
      end

    end

  end
end

describe_pattern "S3_ACCESS_LOG", ['legacy', 'ecs-v1'] do

  context "parsing GET.VERSIONING message" do

    let(:message) do
      "79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - \"GET /mybucket?versioning HTTP/1.1\" 200 - 113 - 7 - \"-\" \"S3Console/0.4\" -"
    end

    it { should include("owner" => "79a5" ) unless ecs_compatibility? }
    it { should include("bucket" => "mybucket" ) unless ecs_compatibility? }
    it { should include("timestamp" => "06/Feb/2014:00:00:38 +0000" ) unless ecs_compatibility? }
    it { should include("clientip" => "192.0.2.3" ) unless ecs_compatibility? }
    it { should include("requester" => "79a5" ) unless ecs_compatibility? }
    it { should include("request_id" => "3E57427F3EXAMPLE" ) unless ecs_compatibility? }
    it { should include("operation" => "REST.GET.VERSIONING" ) unless ecs_compatibility? }
    it { should include("key" => "-" ) unless ecs_compatibility? }

    it { should include("verb" => "GET" ) unless ecs_compatibility? }
    it { should include("request" => "/mybucket?versioning" ) unless ecs_compatibility? }
    it { should include("httpversion" => "1.1" ) unless ecs_compatibility? }
    it { should include("response" => 200 ) unless ecs_compatibility? }
    it { should include("bytes" => 113 ) unless ecs_compatibility? }

    it { should include("request_time_ms" => 7 ) unless ecs_compatibility? }
    it { should include("referrer" => "\"-\"" ) unless ecs_compatibility? }
    it { should include("agent" => "\"S3Console/0.4\"" ) unless ecs_compatibility? }

    ["tags", "error_code", "object_size", "turnaround_time_ms", "version_id"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil unless ecs_compatibility?
      end
    end

  end

  context "parsing a GET.OBJECT message" do

    let(:message) do
      "79a5 mybucket [12/May/2014:07:54:01 +0000] 10.0.1.2 - 7ACC4BE89EXAMPLE REST.GET.OBJECT foo/bar.html \"GET /foo/bar.html HTTP/1.1\" 304 - - 1718 10 - \"-\" \"Mozilla/5.0\" -"
    end

    it do
      if ecs_compatibility?
        should include("aws"=>{"s3access"=>hash_including("bucket_owner" => "79a5")})
      else
        should include("owner" => "79a5")
      end
    end

    it { should include("bucket" => "mybucket" ) unless ecs_compatibility? }
    it { should include("timestamp" => "12/May/2014:07:54:01 +0000" ) }

    it { should include("clientip" => "10.0.1.2" ) unless ecs_compatibility? }
    it { should include("requester" => "-" ) unless ecs_compatibility? }
    it { should include("client" => { 'ip' => '10.0.1.2' } ) if ecs_compatibility? }

    it { should include("request_id" => "7ACC4BE89EXAMPLE" ) unless ecs_compatibility? }
    it { should include("operation" => "REST.GET.OBJECT" ) unless ecs_compatibility? }

    it do
      if ecs_compatibility?
        should include("aws"=>{"s3access"=>hash_including("key" => "foo/bar.html")})
      else
        should include("key" => "foo/bar.html")
      end
    end

    it { should include("verb" => "GET" ) unless ecs_compatibility? }
    it { should include("request" => "/foo/bar.html" ) unless ecs_compatibility? }
    it { should include("httpversion" => "1.1" ) unless ecs_compatibility? }
    it { should include("response" => 304 ) unless ecs_compatibility? }
    it { should include("object_size" => 1718 ) unless ecs_compatibility? }

    it { should include("request_time_ms" => 10 ) unless ecs_compatibility? }
    it { should include("referrer" => "\"-\"" ) unless ecs_compatibility? }

    it { should include("agent" => "\"Mozilla/5.0\"" ) unless ecs_compatibility? }
    it { should include("user_agent"=>{"original"=>"Mozilla/5.0"}) if ecs_compatibility? }

    ["tags", "error_code", "turnaround_time_ms", "version_id", "bytes"].each do |attribute|
      it "have #{attribute} as nil" do
        expect(subject[attribute]).to be_nil unless ecs_compatibility?
      end
    end

  end

  context 'a long line' do

    let(:message) do
      '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket1 [06/Feb/2019:00:00:38 +0000] ' +
      '192.0.2.3 arn:aws:iam::123456:user/test@elastic.co A1206F460EXAMPLE REST.GET.BUCKETPOLICY - ' +
      '"GET /awsexamplebucket1?policy HTTP/1.1" 404 NoSuchBucketPolicy 297 - 38 12 "-" ' +
      '"AWS-Support-TrustedAdvisor, aws-internal/3 aws-sdk-java/1.11.590 Linux/4.9.137-0.1.ac.218.74.329.metal1.x86_64" - ' +
      'BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa3sLLeMC78iwEIWxs99CRUrbS4n11234= SigV2 ECDHE-RSA-AES128-GCM-SHA256 ' +
      'AuthHeader awsexamplebucket1.s3.us-west-1.amazonaws.com TLSV1.1'
    end

    it 'matches' do
      if ecs_compatibility?
        expect(grok).to include("client"=>{"ip"=>"192.0.2.3", "user"=>{"id"=>"arn:aws:iam::123456:user/test@elastic.co"}})
        expect(grok).to include("http"=>{"request"=>{"method"=>"GET"}, "version"=>"1.1", "response"=>{"status_code"=>404}})
        expect(grok).to include("url"=>{"original"=>"/awsexamplebucket1?policy"})
        expect(grok).to include("event"=>{"duration"=>38})
        expect(grok).to include("aws"=>{"s3access"=>{
            "bucket_owner"=>"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
            "bucket"=>"awsexamplebucket1",
            "request_id"=>"A1206F460EXAMPLE",
            "operation"=>"REST.GET.BUCKETPOLICY",
            "turn_around_time"=>12,
            "bytes_sent"=>297,
            "request_uri"=>"GET /awsexamplebucket1?policy HTTP/1.1", # NOTE: redundant (beats compatibility)
            "error_code"=>"NoSuchBucketPolicy",
            # these fields weren't matched in legacy mode:
            # Host Id -> Signature Version -> Cipher Suite -> Authentication Type -> Host Header -> TLS version
            "host_id" => "BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa3sLLeMC78iwEIWxs99CRUrbS4n11234=",
            "signature_version" => "SigV2",
            "cipher_suite" => "ECDHE-RSA-AES128-GCM-SHA256",
            "authentication_type" => "AuthHeader",
            "host_header" => "awsexamplebucket1.s3.us-west-1.amazonaws.com",
            "tls_version" => "TLSV1.1"
        }})
        expect(grok).to include("user_agent"=>{
            "original"=>"AWS-Support-TrustedAdvisor, aws-internal/3 aws-sdk-java/1.11.590 Linux/4.9.137-0.1.ac.218.74.329.metal1.x86_64"
        })
      else
        expect(grok).to include("owner"=>"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
                                "bucket"=>"awsexamplebucket1",
                                "timestamp"=>"06/Feb/2019:00:00:38 +0000",
                                "clientip"=>"192.0.2.3",
                                "requester"=>"arn:aws:iam::123456:user/test@elastic.co",
                                "request_id"=>"A1206F460EXAMPLE",
                                "operation"=>"REST.GET.BUCKETPOLICY",
                                "key"=>"-",
                                "verb"=>"GET",
                                "request"=>"/awsexamplebucket1?policy",
                                "httpversion"=>"1.1",
                                "response"=>404,
                                "error_code"=>"NoSuchBucketPolicy",
                                "bytes"=>297,
                                # object_size nil
                                "request_time_ms"=>38,
                                "turnaround_time_ms"=>12,
                                "referrer"=>"\"-\"",
                                "agent"=>"\"AWS-Support-TrustedAdvisor, aws-internal/3 aws-sdk-java/1.11.590 Linux/4.9.137-0.1.ac.218.74.329.metal1.x86_64\"")
      end
    end

  end
end

describe_pattern "CLOUDFRONT_ACCESS_LOG", ['legacy', 'ecs-v1'] do

  let(:message) do
    "2016-06-10	18:41:39	IAD53	224281	192.168.1.1	GET	d27enomp470abc.cloudfront.net	/content/sample/thing.pdf	200	https://example.com/	Mozilla/5.0%2520(Windows%2520NT%25206.1;%2520WOW64)%2520AppleWebKit/537.36%2520(KHTML,%2520like%2520Gecko)%2520Chrome/51.0.2704.79%2520Safari/537.36	-	-	Miss	UGskZ6dUKY7b4C6Pt7wAWVsU2KO-vTRe-mR4r9H-WQMjhNvY6w1Xcg==	host.example.com	https	883	0.036	-	TLSv1.2	ECDHE-RSA-AES128-GCM-SHA256	RefreshHit"
  end

  it 'matches' do
    should include("timestamp" => "2016-06-10	18:41:39" )

    if ecs_compatibility?
      should include("aws"=>{"cloudfront"=>hash_including("x_edge_location"=>"IAD53")})
      should include("destination"=>{"bytes"=>224281})
      should include("source"=>{"ip"=>"192.168.1.1", "bytes"=>883})
      should include("http"=>{
          "request"=>{"method"=>"GET", "referrer"=>"https://example.com/"},
          "response"=>{"status_code"=>200}
      })
      should include("user_agent"=>{"original"=>"Mozilla/5.0%2520(Windows%2520NT%25206.1;%2520WOW64)%2520AppleWebKit/537.36%2520(KHTML,%2520like%2520Gecko)%2520Chrome/51.0.2704.79%2520Safari/537.36"})
      should include("url"=>{"domain"=>"d27enomp470abc.cloudfront.net", "path"=>"/content/sample/thing.pdf"})
      should include("aws"=>{"cloudfront"=>hash_including("x_edge_result_type"=>"Miss")})
      should include("event"=>{"id"=>"UGskZ6dUKY7b4C6Pt7wAWVsU2KO-vTRe-mR4r9H-WQMjhNvY6w1Xcg=="}) # TODO rather aws.cloudfront.http.request.id ?
      should include("network"=>{"protocol"=>"https"})
      should include("aws"=>{"cloudfront"=>hash_including("http"=>{"request"=>{"host"=>"host.example.com"}})})
      should include("aws"=>{"cloudfront"=>hash_including("time_taken"=>0.036)})
      should include("aws"=>{"cloudfront"=>hash_including("ssl_protocol"=>"TLSv1.2")})
      should include("tls"=>{"cipher"=>"ECDHE-RSA-AES128-GCM-SHA256"})
      should include("aws"=>{"cloudfront"=>hash_including("x_edge_response_result_type"=>"RefreshHit")})
    else
      should include("x_edge_location" => "IAD53" )
      should include("sc_bytes" => 224281 )
      should include("clientip" => "192.168.1.1" )
      should include("cs_method" =>  "GET" )
      should include("cs_host" => "d27enomp470abc.cloudfront.net" )
      should include("cs_uri_stem" => "/content/sample/thing.pdf" )
      should include("sc_status" => 200 )
      should include("referrer" => "https://example.com/" )
      should include("agent" => "Mozilla/5.0%2520(Windows%2520NT%25206.1;%2520WOW64)%2520AppleWebKit/537.36%2520(KHTML,%2520like%2520Gecko)%2520Chrome/51.0.2704.79%2520Safari/537.36" )
      should include("cs_uri_query" => "-" )
      should include("cookies" => "-" )
      should include("x_edge_result_type" => "Miss" )
      should include("x_edge_request_id" => "UGskZ6dUKY7b4C6Pt7wAWVsU2KO-vTRe-mR4r9H-WQMjhNvY6w1Xcg==" )
      should include("x_host_header" => "host.example.com" )
      should include("cs_protocol" => "https" )
      should include("cs_bytes" => 883 )
      should include("time_taken" => 0.036 )
      should include("x_forwarded_for" => "-" )
      should include("ssl_protocol" => "TLSv1.2" )
      should include("ssl_cipher" => "ECDHE-RSA-AES128-GCM-SHA256" )
      should include("x_edge_response_result_type" => "RefreshHit" )
    end
  end

  ["tags", "params"].each do |attribute|
    it "have #{attribute} as nil" do
      expect(subject[attribute]).to be_nil
    end
  end

  context 'version 1.0' do # more fields at the end

    let(:message) do
      # Version: 1.0  -  https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
      # Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie) x-edge-result-type x-edge-request-id x-host-header cs-protocol cs-bytes time-taken x-forwarded-for ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version fle-status fle-encrypted-fields c-port time-to-first-byte x-edge-detailed-result-type sc-content-type sc-content-len sc-range-start sc-range-end
      "2019-12-04	21:02:31	LAX1	392	192.0.2.100	GET	d111111abcdef8.cloudfront.net	/index.html	200	-	Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/78.0.3904.108%20Safari/537.36	-	-	Hit	SOX4xwn4XV6Q4rgb7XiVGOHms_BGlTAC4KyHmureZmBNrjGdRLiNIQ==	d111111abcdef8.cloudfront.net	https	23	0.001	-	TLSv1.2	ECDHE-RSA-AES128-GCM-SHA256	Hit	HTTP/2.0	-	-	11040	0.001	Hit	text/html	78	-	-"
    end

    it 'matches' do
      should include("timestamp" => "2019-12-04\t21:02:31")

      if ecs_compatibility?
        should include("destination"=>{"bytes"=>392}, "source"=>{"ip"=>"192.0.2.100", "bytes"=>23, "port"=>11040}) # source.port not matched in legacy mode
        should include("url"=>{"domain"=>"d111111abcdef8.cloudfront.net", "path"=>"/index.html"})
        should include("http"=>hash_including("request"=>{"mime_type"=>"text/html", "method"=>"GET"}, "response"=>{"status_code"=>200})) # mime_type not matched in legacy mode
        should include("user_agent"=>{"original"=>"Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/78.0.3904.108%20Safari/537.36"})
        should include("tls"=>{"cipher"=>"ECDHE-RSA-AES128-GCM-SHA256"})
        should include("network"=>{"protocol"=>"https"})

        should include("http"=>hash_including("version"=>"2.0"))
        should include("aws"=>{"cloudfront"=>{
            "x_edge_location"=>"LAX1",
            "x_edge_result_type"=>"Hit",
            "x_edge_response_result_type"=>"Hit",
            "x_edge_detailed_result_type"=>"Hit", # not captured in legacy mode
            "time_taken"=>0.001,
            "time_to_first_byte"=>0.001, # not captured in legacy mode
            "http"=>{"request"=>{"host"=>"d111111abcdef8.cloudfront.net", "size"=>78}}, # http.request.size not captured in legacy mode
            "ssl_protocol"=>"TLSv1.2",
        }})
      else
        should include("cs_method"=>"GET", "cs_host"=>"d111111abcdef8.cloudfront.net", "cs_uri_stem"=>"/index.html", "cs_protocol"=>"https", "cs_bytes"=>23)
        should include("x_host_header"=>"d111111abcdef8.cloudfront.net")
        should include("time_taken"=>0.001)
        should include("x_edge_request_id"=>"SOX4xwn4XV6Q4rgb7XiVGOHms_BGlTAC4KyHmureZmBNrjGdRLiNIQ==")
        should include("agent"=>"Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/78.0.3904.108%20Safari/537.36")

        should include("x_forwarded_for"=>"text/html") # TODO the legacy pattern does not handle the long(er) format correctly
      end
    end

  end

end
