# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "CISCOFW104001" do

  let(:message) { "(Secondary) Switching to ACTIVE - Service card in other unit has failed" }

  it { should include("switch_reason" => "Service card in other unit has failed") }

  it "generates a message field" do
    expect(subject["message"]).to include("(Secondary) Switching to ACTIVE - Service card in other unit has failed")
  end

end

describe_pattern "CISCOFW106015" do

  let(:message) { "Deny TCP (no connection) from 192.168.150.65/2278 to 64.101.128.83/80 flags RST on interface inside" }

  it { should include("interface" => "inside") }

  it "generates a message field" do
    expect(subject["message"]).to include("Deny TCP (no connection) from 192.168.150.65/2278 to 64.101.128.83/80 flags RST on interface inside")
  end

end

describe_pattern "CISCOFW106100" do

  let(:message) { "access-list inside permitted tcp inside/10.10.123.45(51763) -> outside/192.168.67.89(80) hit-cnt 1 first hit [0x62c4905, 0x0]" }

  it { should include("policy_id" => "inside") }

  it "generates a message field" do
    expect(subject["message"]).to include("access-list inside permitted tcp inside/10.10.123.45(51763) -> outside/192.168.67.89(80) hit-cnt 1 first hit [0x62c4905, 0x0]")
  end

end

describe_pattern "CISCOFW106100" do

  let(:message) { "access-list outside-entry permitted tcp outside/10.11.12.13(54726) -> inside/192.168.17.18(80) hit-cnt 1 300-second interval [0x32b3835, 0x0]" }

  it { should include("policy_id" => "outside-entry") }

  it "generates a message field" do
    expect(subject["message"]).to include("access-list outside-entry permitted tcp outside/10.11.12.13(54726) -> inside/192.168.17.18(80) hit-cnt 1 300-second interval [0x32b3835, 0x0]")
  end

end

describe_pattern "CISCOFW304001" do

  let(:message) { "10.20.30.40(DOMAIN\\login) Accessed URL 10.11.12.13:http://example.org/" }

  it 'should break the message up into fields' do
    expect(subject['src_ip']).to eq('10.20.30.40')
    expect(subject['src_fwuser']).to eq('DOMAIN\\login')
    expect(subject['dst_ip']).to eq('10.11.12.13')
    expect(subject['dst_url']).to eq('http://example.org/')
  end

end

describe_pattern "CISCOFW106023" do

  let(:message) { 'Deny tcp src outside:192.168.1.1/50240 dst inside:192.168.1.2/23 by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]' }

  it 'should break the message up into fields' do
    expect(subject['action']).to eq('Deny')
    expect(subject['src_interface']).to eq('outside')
    expect(subject['dst_interface']).to eq('inside')
    expect(subject['protocol']).to eq('tcp')
    expect(subject['src_ip']).to eq('192.168.1.1')
    expect(subject['dst_ip']).to eq('192.168.1.2')
    expect(subject['policy_id']).to eq('S_OUTSIDE_TO_INSIDE')
  end

  context "a message with a protocol number" do

    let(:message) { 'Deny protocol 103 src outside:192.168.1.1/50240 dst inside:192.168.1.2/23 by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]' }

    it 'should break the message up into fields' do
      expect(subject['action']).to eq('Deny')
      expect(subject['src_interface']).to eq('outside')
      expect(subject['dst_interface']).to eq('inside')
      expect(subject['protocol']).to eq('103')
      expect(subject['src_ip']).to eq('192.168.1.1')
      expect(subject['dst_ip']).to eq('192.168.1.2')
      expect(subject['policy_id']).to eq('S_OUTSIDE_TO_INSIDE')
    end
  end


  context "a message with a hostname" do

    let(:message) { 'Deny tcp src outside:192.168.1.1/50240 dst inside:www.example.com/23 by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]' }

    it 'should break the message up into fields' do
      expect(subject['action']).to eq('Deny')
      expect(subject['src_interface']).to eq('outside')
      expect(subject['dst_interface']).to eq('inside')
      expect(subject['protocol']).to eq('tcp')
      expect(subject['src_ip']).to eq('192.168.1.1')
      expect(subject['dst_ip']).to eq('www.example.com')
      expect(subject['policy_id']).to eq('S_OUTSIDE_TO_INSIDE')
    end
  end

end
