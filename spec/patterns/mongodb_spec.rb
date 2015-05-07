# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "MONGO3_LOG" do

  let(:pattern)    { "MONGO3_LOG" }

  context "parsing an standard/basic message" do

    let(:value) { "2014-11-03T18:28:32.450-0500 I NETWORK [initandlisten] waiting for connections on port 27017" }

    subject     { grok_match(pattern, value) }

    it { should include("timestamp" => "2014-11-03T18:28:32.450-0500") }

    it { should include("severity" => "I") }

    it { should include("component" => "NETWORK") }

    it { should include("context" => "initandlisten") }

    it "generates a message field" do
      expect(subject["message"]).to include("waiting for connections on port 27017")
    end
  end

  context "parsing a message with a missing component" do

    let(:value) { "2015-02-24T18:17:47.148+0000 F -        [conn11] Got signal: 11 (Segmentation fault)." }

    subject     { grok_match(pattern, value) }

    it { should include("timestamp" => "2015-02-24T18:17:47.148+0000") }

    it { should include("severity" => "F") }

    it { should include("component" => "-") }

    it { should include("context" => "conn11") }

    it "generates a message field" do
      expect(subject["message"]).to include("Got signal: 11 (Segmentation fault).")
    end
  end

  context "parsing a message with a multiwords context" do

    let(:value) { "2015-04-23T06:57:28.256+0200 I JOURNAL  [journal writer] Journal writer thread started" }

    subject     { grok_match(pattern, value) }

    it { should include("timestamp" => "2015-04-23T06:57:28.256+0200") }

    it { should include("severity" => "I") }

    it { should include("component" => "JOURNAL") }

    it { should include("context" => "journal writer") }

    it "generates a message field" do
      expect(subject["message"]).to include("Journal writer thread started")
    end
  end

  context "parsing a message without context" do

    let(:value) { "2015-04-23T07:00:13.864+0200 I CONTROL  Ctrl-C signal" }

    subject     { grok_match(pattern, value) }

    it { should include("timestamp" => "2015-04-23T07:00:13.864+0200") }

    it { should include("severity" => "I") }

    it { should include("component" => "CONTROL") }

    it { should_not have_key("context") }

    it "generates a message field" do
      expect(subject["message"]).to include("Ctrl-C signal")
    end
  end
end
