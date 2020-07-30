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
  module PatternModeSupport
    @@pattern_mode = nil
    def pattern_mode
      @@pattern_mode
    end
    module_function :pattern_mode

    def pattern_mode=(mode)
      @@pattern_mode = mode
    end
  end

  def ecs_compatibility?
    case ecs_compatibility
    when :disabled then false
    when nil then nil
    else true
    end
  end

  def ecs_compatibility
    case mode = PatternModeSupport.pattern_mode
    when 'legacy' then :disabled
    when 'ecs-v1' then :v1
    when nil then nil
    else fail "pattern_mode: #{mode.inspect}"
    end
  end

  def grok_match(label, message, exact_match = false)
    grok  = build_grok(label, exact_match)
    event = build_event(message)
    grok.filter(event)
    event.to_hash
  end

  def build_grok(label, exact_match = false)
    grok_opts = { "match" => [ "message", exact_match ? "^%{#{label}}$" : "%{#{label}}" ] }
    ecs_compat = ecs_compatibility # if not set use the plugin default
    grok_opts["ecs_compatibility"] = ecs_compat unless ecs_compat.nil?
    grok = LogStash::Filters::Grok.new(grok_opts)
    grok.register
    grok
  end

  def build_event(message)
    LogStash::Event.new("message" => message)
  end
end

RSpec.configure do |c|
  c.include GrokHelpers
  c.include GrokHelpers::PatternModeSupport
  c.extend GrokHelpers::PatternModeSupport
end

def describe_pattern(name, pattern_modes = [ nil ], &block)
  pattern_modes.each do |mode|
    RSpec.describe "#{name}#{mode ? " (#{mode})" : nil}" do

      before(:each) do
        @restore_pattern_mode = pattern_mode
        self.pattern_mode = mode
      end
      after(:each) do
        self.pattern_mode = @restore_pattern_mode
      end

      let(:pattern) { name }
      let(:message) { raise 'let(:message) { ... } is missing' }
      let(:grok) { grok_match(pattern, message) }

      instance_eval(&block)
    end
  end
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

