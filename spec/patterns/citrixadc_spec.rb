# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "CIRIXADC" do

  let(:citrixadc_pattern)  { "CITRIXADC_LOG" }

  context "Parsing Citrix ADC log line from raw syslog line" do

    let(:value) { '"<134> 08/02/2020:14:53:24  vpx 0-PPE-0 : default CLI CMD_EXECUTED 1488010 0 :  User nsroot - Remote_ip 192.168.0.1 - Command \"save ns config\" - Status \"Success\"\n"' }
    subject     { grok_match(citrixadc_pattern, value) }

    it { should include("CitrixAdcHostname" => "vpx") }
    it { should include("CitrixAdcModule" => "CLI") }
    it { should include("CitrixAdcEventType" => "CMD_EXECUTED") }

  end

end
