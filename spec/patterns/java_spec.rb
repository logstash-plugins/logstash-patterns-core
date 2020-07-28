# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "JAVA" do
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
end

describe "JAVASTACKTRACEPART" do
  let(:pattern) { 'JAVASTACKTRACEPART' }
  let(:message) { '  at com.sample.stacktrace.StackTraceExample.aMethod(StackTraceExample.java:42)' }
  it "matches" do
    grok = grok_match(pattern, message, true)
    expect(grok).to include({
                                "message"=>"  at com.sample.stacktrace.StackTraceExample.aMethod(StackTraceExample.java:42)",
                                "method"=>"aMethod",
                                "class"=>"com.sample.stacktrace.StackTraceExample",
                                "file"=>"StackTraceExample.java",
                                "line"=>"42"
                            })
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