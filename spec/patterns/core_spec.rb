# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require 'logstash/patterns/core'

describe LogStash::Patterns::Core do
  describe "s3 access log format" do
    config <<-CONFIG
    filter {
      grok {
        match => [ "message", "%{S3_ACCESS_LOG}" ]
      }
    }
    CONFIG

    sample "79a5 mybucket [06/Feb/2014:00:00:38 +0000] 192.0.2.3 79a5 3E57427F3EXAMPLE REST.GET.VERSIONING - \"GET /mybucket?versioning HTTP/1.1\" 200 - 113 - 7 - \"-\" \"S3Console/0.4\" -" do
      insist { subject["tags"] }.nil?
      insist { subject["owner"] } == "79a5"
      insist { subject["bucket"] } == "mybucket"
      insist { subject["timestamp"] } == "06/Feb/2014:00:00:38 +0000"
      insist { subject["clientip"] } == "192.0.2.3"
      insist { subject["requester"] } == "79a5"
      insist { subject["request_id"] } == "3E57427F3EXAMPLE"
      insist { subject["operation"] } == "REST.GET.VERSIONING"
      insist { subject["key"] } == '-'
      insist { subject["verb"] } == "GET"
      insist { subject["request"] } == "/mybucket?versioning"
      insist { subject["httpversion"] } == "1.1"
      insist { subject["response"] } == 200
      insist { subject["error_code"] }.nil?
      insist { subject["bytes"] } == 113
      insist { subject["object_size"] }.nil?
      insist { subject["request_time_ms"] } == 7
      insist { subject["turnaround_time_ms"] }.nil?
      insist { subject["referrer"] } == "\"-\""
      insist { subject["agent"] } == "\"S3Console/0.4\""
      insist { subject["version_id"] }.nil?
    end

    sample "79a5 mybucket [12/May/2014:07:54:01 +0000] 10.0.1.2 - 7ACC4BE89EXAMPLE REST.GET.OBJECT foo/bar.html \"GET /foo/bar.html HTTP/1.1\" 304 - - 1718 10 - \"-\" \"Mozilla/5.0\" -" do
      insist { subject["tags"] }.nil?
      insist { subject["owner"] } == "79a5"
      insist { subject["bucket"] } == "mybucket"
      insist { subject["timestamp"] } == "12/May/2014:07:54:01 +0000"
      insist { subject["clientip"] } == "10.0.1.2"
      insist { subject["requester"] } == "-"
      insist { subject["request_id"] } == "7ACC4BE89EXAMPLE"
      insist { subject["operation"] } == "REST.GET.OBJECT"
      insist { subject["key"] } == "foo/bar.html"
      insist { subject["verb"] } == "GET"
      insist { subject["request"] } == "/foo/bar.html"
      insist { subject["httpversion"] } == "1.1"
      insist { subject["response"] } == 304
      insist { subject["error_code"] }.nil?
      insist { subject["bytes"] }.nil?
      insist { subject["object_size"] } == 1718
      insist { subject["request_time_ms"] } == 10
      insist { subject["turnaround_time_ms"] }.nil?
      insist { subject["referrer"] } == "\"-\""
      insist { subject["agent"] } == "\"Mozilla/5.0\""
      insist { subject["version_id"] }.nil?
    end
  end

  describe "elb access log format" do
    config <<-CONFIG
     filter {
       grok {
         match => ["message", "%{ELB_ACCESS_LOG}"]
       }
     }
    CONFIG

    sample "2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 \"GET http://www.example.com:80/ HTTP/1.1\"" do
      insist { subject["tags"] }.nil?
      insist { subject["timestamp"] } == "2014-02-15T23:39:43.945958Z"
      insist { subject["elb"] } == "my-test-loadbalancer"
      insist { subject["clientip"] } == "192.168.131.39"
      insist { subject["clientport"] } == 2817
      insist { subject["backendip"] } == "10.0.0.1"
      insist { subject["backendport"] } == 80
      insist { subject["request_processing_time"] } == 0.000073
      insist { subject["backend_processing_time"] } == 0.001048
      insist { subject["response_processing_time"] } == 0.000057
      insist { subject["response"] } == 200
      insist { subject["backend_response"] } == 200
      insist { subject["received_bytes"] } == 0
      insist { subject["bytes"] } == 29
      insist { subject["verb"] } == "GET"
      insist { subject["request"] } == "http://www.example.com:80/"
      insist { subject["proto"] } == "http"
      insist { subject["httpversion"] } == "1.1"
      insist { subject["urihost"] } == "www.example.com:80"
      insist { subject["path"] } == "/"
      insist { subject["params"] }.nil?
    end
  end
end
