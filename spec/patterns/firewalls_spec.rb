# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "FIREWALLS" do

  let(:pattern)    { "CISCOFW104001" }

  context "parsing a 104001 message" do

    let(:value) { "(Secondary) Switching to ACTIVE - Service card in other unit has failed" }

    subject     { grok_match(pattern, value) }

    it { should include("switch_reason" => "Service card in other unit has failed") }

    it "generates a message field" do
      expect(subject["message"]).to include("(Secondary) Switching to ACTIVE - Service card in other unit has failed")
    end
  end

end
