# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "MAVEN_VERSION" do

  let(:pattern) { 'MAVEN_VERSION' }

  context "when maven version is simple" do
    let(:value) { '1.1.0' }

    it "should match the version" do
      expect(grok_match(pattern,value)).to pass
    end
  end

  context "when maven version is a bit more complex" do
    let(:value) { '2.35.128' }

    it "should match the version" do
      expect(grok_match(pattern,value)).to pass
    end
  end

  context "when maven version contains release" do
    let(:value) { '1.1.0.RELEASE' }

    it "should match the version" do
      expect(grok_match(pattern,value)).to pass
    end
  end

  context "when maven version contains shapshot" do
    let(:value) { '1.1.0.SNAPSHOT' }

    it "should match the version" do
      expect(grok_match(pattern,value)).to pass
    end
  end

  context "when maven version contains release" do
    context "and the version contains a dash" do
      let(:value) { '1.1.0-RELEASE' }

      it "should match the version" do
        expect(grok_match(pattern,value)).to pass
      end
    end
  end

  context "when maven version contains shapshot" do
    context "and the version contains a dash" do
    let(:value) { '1.1.0-SNAPSHOT' }

      it "should match the version" do
        expect(grok_match(pattern,value)).to pass
      end
    end
  end

end
