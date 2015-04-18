require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/grok"
require 'rspec/expectations'

module GrokHelpers
  def grok_match(label, message)
    grok  = build_grok(label)
    event = build_event(message)
    grok.filter(event)
    event.to_hash
  end

  def build_grok(label)
    grok = LogStash::Filters::Grok.new("match" => ["message", "%{#{label}}"])
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

