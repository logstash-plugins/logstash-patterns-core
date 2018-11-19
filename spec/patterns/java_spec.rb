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
