# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require 'logstash/patterns/core'

describe LogStash::Patterns::Core do
  describe "rfc822 dates" do
    config <<-CONFIG
      filter {
        grok {
          match => {
            "message" => [
              "%{DATESTAMP_RFC2822}",
              "%{MONTH} %{MONTHDAY} %{HOUR}:%{MINUTE}:%{SECOND}"
            ]
          }
          named_captures_only => false
        }
      }
    CONFIG

    sample "Mon, 12 May 2014 17:00:32 -0500" do
      insist { subject["DATESTAMP_RFC2822"] } == "Mon, 12 May 2014 17:00:32 -0500"
      insist { subject["MONTHDAY"] } == "12"
    end

    # As occurs in a syslog/maillog message such as:
    # lmtpunix[$pid]: dupelim: eliminated duplicate message to domain!user.john <message-id> date Mon, 5 May 2014 17:00:32 -0500 (delivery)
    sample "Mon, 5 May 2014 17:00:32 -0500" do
      insist { subject["DATESTAMP_RFC2822"] } == "Mon, 5 May 2014 17:00:32 -0500"
      insist { subject["MONTHDAY"] } == "5"
    end

    # As might occur in a syslog/maillog message such as:
    # postfix/anvil[$pid]: statistics: max cache size 28 at May  6 00:02:47
    # Note: The match will have a space, but this does not prevent conversion to integer.
    sample "May  6 00:02:47" do
      insist { subject["MONTHDAY"] } == " 6"
    end

    # With a 0 prefix
    sample "May 06 00:02:47" do
      insist { subject["MONTHDAY"] } == "06"
    end

  end

end
