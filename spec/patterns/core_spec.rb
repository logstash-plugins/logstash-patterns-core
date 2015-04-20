# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require 'logstash/patterns/core'

describe LogStash::Patterns::Core do
  describe "Dates with time zone are correctly interpreted" do
    config <<-CONFIG
      filter {
        grok {
          match => [ "message",  "%{DATESTAMP_RFC822:stimestamp}" ]
          singles => true
        }
      }
    CONFIG
    sample "Tue Jan 01 2013 04:51:39 CEST" do
      insist { subject["stimestamp"] }== "Tue Jan 01 2013 04:51:39 CEST"
    end
    sample "Tue Jan 01 2013 04:51:39 CET" do
      insist { subject["stimestamp"] }== "Tue Jan 01 2013 04:51:39 CET"
      end
    sample "Tue Jan 01 2013 04:51:39 UTC" do
      insist { subject["stimestamp"] }== "Tue Jan 01 2013 04:51:39 UTC"
    end
  end
end
