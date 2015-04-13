# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/patterns/core"
require "logstash/filters/grok"
require "spec/helper"

test_message "IPORHOST", "127.0.0.1"
