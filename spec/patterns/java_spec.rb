# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "JAVACLASS" do
  let(:example) { 'hudson.node_monitors.AbstractAsyncNodeMonitorDescriptor' }
  it "matches a java class with underscores" do
    expect(grok_match(subject, example, true)['tags']).to be_nil
  end
end
describe "JAVAFILE" do
  let(:example) { 'Native Method' }
  it "matches a java file name with spaces" do
    expect(grok_match(subject, example, true)['tags']).to be_nil
  end
end

describe_pattern "JAVASTACKTRACEPART", [ 'legacy', 'ecs-v1' ] do
  let(:message) { '  at com.sample.stacktrace.StackTraceExample.aMethod(StackTraceExample.java:42)' }

  it "matches" do
    if ecs_compatibility?
      expect(grok).to include(
                          "log" => { "origin" => { "function" => 'aMethod', "file" => { "name" => 'StackTraceExample.java', "line" => 42 } } },
                          "java" => { "log" => { "origin" => { "class" => { "name" => 'com.sample.stacktrace.StackTraceExample' } } } }
                      )
    else
      expect(grok).to include(
                          "message"=>"  at com.sample.stacktrace.StackTraceExample.aMethod(StackTraceExample.java:42)",
                          "method"=>"aMethod",
                          "class"=>"com.sample.stacktrace.StackTraceExample",
                          "file"=>"StackTraceExample.java",
                          "line"=>"42"
                      )
    end
  end

  context 'generated file' do
    let(:message) { '  at org.jruby.RubyMethod$INVOKER$i$call.call(RubyMethod$INVOKER$i$call.gen)' }
    it "matches" do
      grok = grok_match(pattern, message, true)
      expect(grok).to include({
                                  "method"=>"call",
                                  "class"=>"org.jruby.RubyMethod$INVOKER$i$call",
                                  "file"=>"RubyMethod$INVOKER$i$call.gen",
                              })
    end
  end
end