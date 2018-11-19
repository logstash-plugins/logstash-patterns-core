require "logstash/devutils/rspec/spec_helper"
require 'rspec/expectations'

# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../", __FILE__)
end

# temporary fix to have the spec pass for an urgen mass-publish requirement.
# cut & pasted from the same tmp fix in the grok spec
# see https://github.com/logstash-plugins/logstash-filter-grok/issues/72
# this needs to be refactored and properly fixed
module LogStash::Environment
  # also :pattern_path method must exist so we define it too
  unless self.method_defined?(:pattern_path)
    def pattern_path(path)
      ::File.join(LOGSTASH_HOME, "patterns", path)
    end
  end
end

require "logstash/filters/grok"

module GrokHelpers
  def grok_match(label, message, exact_match = false)
    grok  = build_grok(label, exact_match)
    event = build_event(message)
    grok.filter(event)
    event.to_hash
  end

  def build_grok(label, exact_match = false)
    if exact_match
      grok = LogStash::Filters::Grok.new("match" => ["message", "^%{#{label}}$"])
    else
      grok = LogStash::Filters::Grok.new("match" => ["message", "%{#{label}}"])
    end
    grok.register
    grok
  end

  def build_event(message)
    LogStash::Event.new("message" => message)
  end
end

RSpec.configure do |c|
  c.include GrokHelpers
end

RSpec::Matchers.define :pass do |expected|
  match do |actual|
    !actual.include?("tags")
  end
end

RSpec::Matchers.define :match do |value|
  match do |grok|
    grok  = build_grok(grok)
    event = build_event(value)
    grok.filter(event)
    !event.include?("tags")
  end
end

