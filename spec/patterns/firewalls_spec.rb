# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES = ['event', 'cisco', 'observer', 'source', 'destination'].freeze

describe_pattern "CISCOFW104001", ['legacy', 'ecs-v1'] do

  let(:message) { "(Secondary) Switching to ACTIVE - Service card in other unit has failed" }

  include_examples 'top-level namespaces', ['event'], if: -> { ecs_compatibility? }

  it { expect(subject).to include("switch_reason" => "Service card in other unit has failed") unless ecs_compatibility? }

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106001", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-2-106001: Inbound TCP connection denied from 192.168.2.2/43803 to 10.10.10.10/14322 flags SYN on interface out111" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"192.168.2.2", "port"=>43803}
      expect(subject).to include "destination"=>{"ip"=>"10.10.10.10", "port"=>14322}
      expect(subject).to include "observer"=>{"egress"=>{"interface"=>{"name"=>"out111"}}}
      expect(subject).to include "cisco"=>{"asa"=>hash_including("network"=>{"transport"=>"TCP", "direction"=>"Inbound"}, "tcp_flags"=>"SYN")}
    else
      expect(subject).to include("src_ip"=>"192.168.2.2", "src_port"=>'43803')
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106006_106007_106010", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-2-106006: Deny inbound UDP from 192.168.2.2/65020 to 10.10.10.10/65021 on interface fw111" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "cisco" => {"asa"=>{"network"=>{"direction"=>"inbound", "transport"=>"UDP"}, "outcome"=>"Deny"}}
      expect(subject).to include "source"=>{"ip"=>"192.168.2.2", "port"=>65020}
      expect(subject).to include "destination"=>{"ip"=>"10.10.10.10", "port"=>65021}
      expect(subject).to include "observer"=>{"egress"=>{"interface"=>{"name"=>"fw111"}}}
    else
      expect(subject).to include("src_ip"=>"192.168.2.2", "src_port"=>'65020')
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106014", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-3-106014: Deny inbound icmp src fw111:10.10.10.10 dst fw111:10.10.10.11(type 8, code 0)" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"10.10.10.10"}
      expect(subject).to include "destination"=>{"ip"=>"10.10.10.11"}
      expect(subject).to include "cisco"=>{"asa"=>{"outcome"=>"Deny", "network"=>{"transport"=>"icmp", "direction"=>"inbound"}, "icmp_code"=>0, "icmp_type"=>8}}
      expect(subject).to include "observer"=>{"ingress"=>{"interface"=>{"name"=>"fw111"}}, "egress"=>{"interface"=>{"name"=>"fw111"}}}
    else
      # NOTE: does not match due expecting space: "10.10.10.11 (type 8, code 0)"
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106015", ['legacy', 'ecs-v1'] do

  let(:message) { "Deny TCP (no connection) from 192.168.150.65/2278 to 64.101.128.83/80 flags RST on interface eth0" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "observer"=>{"egress"=>{"interface"=>{"name"=>"eth0"}}}
    else
      expect(subject).to include("interface" => "eth0")
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106021", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-4-106021: Deny TCP reverse path check from 192.168.2.2 to 10.10.10.10 on interface fw111" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"192.168.2.2"}, "destination"=>{"ip"=>"10.10.10.10"}
      expect(subject).to include "cisco"=>{"asa"=>{"network"=>{"transport"=>"TCP"}, "outcome"=>"Deny"}}
      expect(subject).to include "observer"=>{"egress"=>{"interface"=>{"name"=>"fw111"}}}
    else
      expect(subject).to include("interface" => "fw111")
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106100", ['legacy', 'ecs-v1'] do

  let(:message) { "access-list inside permitted tcp inside/10.10.123.45(51763) -> outside/192.168.67.89(80) hit-cnt 1 first hit [0x62c4905, 0x0]" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("cisco"=>{"asa"=>hash_including("rule_name" => "inside")})
    else
      expect(subject).to include("policy_id" => "inside")
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106100", ['legacy', 'ecs-v1'] do

  let(:message) { "access-list outside-entry permitted tcp outside/10.11.12.13(54726) -> inside/192.168.17.18(80) hit-cnt 1 300-second interval [0x32b3835, 0x0]" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("cisco"=>{"asa"=>hash_including("rule_name" => "outside-entry")})
    else
      expect(subject).to include("policy_id" => "outside-entry")
    end
  end

  it "keeps message field" do
    expect(subject["message"]).to eql message
  end

end

describe_pattern "CISCOFW106023", ['legacy', 'ecs-v1'] do

  let(:message) { 'Deny tcp src outside:192.168.1.1/50240 dst inside:192.168.1.2/23 by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]' }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"192.168.1.1", "port"=>50240}
      expect(subject).to include "observer"=>{"egress"=>{"interface"=>{"name"=>"inside"}}, "ingress"=>{"interface"=>{"name"=>"outside"}}}
      expect(subject).to include "cisco"=>{"asa"=>{"outcome"=>"Deny", "network"=>{"transport"=>"tcp"}, "rule_name"=>"S_OUTSIDE_TO_INSIDE"}}
    else
      expect(subject['action']).to eq('Deny')
      expect(subject['src_interface']).to eq('outside')
      expect(subject['dst_interface']).to eq('inside')
      expect(subject['protocol']).to eq('tcp')
      expect(subject['src_ip']).to eq('192.168.1.1')
      expect(subject['dst_ip']).to eq('192.168.1.2')
      expect(subject['policy_id']).to eq('S_OUTSIDE_TO_INSIDE')
    end
  end

  context "a message with a protocol number" do

    let(:message) { 'Deny protocol 103 src outside:192.168.1.1/50240 dst inside:192.168.1.2/23 by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]' }

    it 'matches' do
      if ecs_compatibility?
        expect(subject).to include "destination"=>{"ip"=>"192.168.1.2", "port"=>23},
                                   "cisco"=>{"asa"=>{"outcome"=>"Deny", "network"=>{"transport"=>"103"}, "rule_name"=>"S_OUTSIDE_TO_INSIDE"}}
      else
        expect(subject['action']).to eq('Deny')
        expect(subject['src_interface']).to eq('outside')
        expect(subject['dst_interface']).to eq('inside')
        expect(subject['protocol']).to eq('103')
        expect(subject['src_ip']).to eq('192.168.1.1')
        expect(subject['dst_ip']).to eq('192.168.1.2')
        expect(subject['policy_id']).to eq('S_OUTSIDE_TO_INSIDE')
      end
    end
  end


  context "a message with a hostname" do

    let(:message) { 'Deny tcp src outside:192.168.1.1/50240 dst inside:www.example.com/23 by access-group "S_OUTSIDE_TO_INSIDE" [0x54c7fa80, 0x0]' }

    it 'matches' do
      if ecs_compatibility?
        expect(subject).to include "destination"=>{"port"=>23, "address"=>"www.example.com"}
        expect(subject).to include "source"=>{"port"=>50240, "ip"=>"192.168.1.1"}
        expect(subject).to include "observer"=>{"ingress"=>{"interface"=>{"name"=>"outside"}}, "egress"=>{"interface"=>{"name"=>"inside"}}}
      else
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

end

describe_pattern "CISCOFW304001", ['legacy', 'ecs-v1'] do

  let(:message) { "10.20.30.40(DOMAIN\\login) Accessed URL 10.11.12.13:http://example.org/" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES + ['url'], if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"10.20.30.40", "user"=>{"name"=>"DOMAIN\\login"}}
      expect(subject).to include "url"=>{"original"=>"http://example.org/"}
    else
      expect(subject['src_ip']).to eq('10.20.30.40')
      expect(subject['src_fwuser']).to eq('DOMAIN\\login')
      expect(subject['dst_ip']).to eq('10.11.12.13')
      expect(subject['dst_url']).to eq('http://example.org/')
    end
  end

end

describe_pattern "CISCOFW110002", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-6-110002: Failed to locate egress interface for TCP from sourceInterfaceName:91.240.17.178/7777 to 192.168.2.2/123412" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "event"=>{"reason"=>"Failed to locate egress interface"}
      expect(subject).to include "cisco"=>{"asa"=>{"network"=>{"transport"=>"TCP"}}}
      expect(subject).to include "source"=>{"port"=>7777, "ip"=>"91.240.17.178"}
      expect(subject).to include "observer"=>{"ingress"=>{"interface"=>{"name"=>"sourceInterfaceName"}}}
      expect(subject).to include "destination"=>{"port"=>123412, "ip"=>"192.168.2.2"}
    else
      expect(subject['src_ip']).to eq('91.240.17.178')
      expect(subject['dst_ip']).to eq('192.168.2.2')
    end
  end

end

describe_pattern "CISCOFW302013_302014_302015_302016", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-6-302013: Built outbound TCP connection 11757 for outside:100.66.205.104/80 (100.66.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"100.66.205.104", "port"=>80, "nat"=>{"ip"=>"100.66.205.104", "port"=>80}}
      expect(subject).to include "cisco"=>{"asa"=>{"network"=>{"direction"=>"outbound", "transport"=>"TCP"}, "outcome"=>"Built", "connection_id"=>"11757"}}
      expect(subject).to include "observer"=>{"egress"=>{"interface"=>{"name"=>"inside"}}, "ingress"=>{"interface"=>{"name"=>"outside"}}}
    else
      expect(subject['src_ip']).to eq('100.66.205.104')
      expect(subject['dst_ip']).to eq('172.31.98.44')
    end
  end

end

describe_pattern "CISCOFW302020_302021", ['legacy', 'ecs-v1'] do

  let(:message) { "302020: Built inbound ICMP connection for faddr 10.137.200.251/18425 gaddr 10.137.10.1/0 laddr 10.137.10.10/0" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("cisco"=>{"asa"=>{
          "outcome"=>"Built", "icmp_seq"=>18425, "network"=>{"direction"=>"inbound", "transport"=>"ICMP"}, "icmp_type"=>0
      }})
      expect(subject).to include("source"=>{"nat"=>{"ip"=>"10.137.10.1"}, "ip"=>"10.137.10.10"}, "destination"=>{"ip"=>"10.137.200.251"})
    else
      expect(subject['src_ip']).to eq('10.137.10.10')
      expect(subject['dst_ip']).to eq('10.137.200.251')
    end
  end

  context '302021' do

    let(:message) { "6|Nov 28 2014 12:59:03|302021: Teardown ICMP connection for faddr 10.137.200.251/18425 gaddr 10.137.10.1/0 laddr 10.137.10.10/0" }

    it 'matches' do
      if ecs_compatibility?
        expect(subject).to include "cisco"=>{"asa"=>{"outcome"=>"Teardown", "network"=>{"transport"=>"ICMP"}, "icmp_seq"=>18425, "icmp_type"=>0}}
        expect(subject).to include "source"=>{"nat"=>{"ip"=>"10.137.10.1"}, "ip"=>"10.137.10.10"}, "destination"=>{"ip"=>"10.137.200.251"}
      else
        expect(subject['src_ip']).to eq('10.137.10.10')
        expect(subject['dst_ip']).to eq('10.137.200.251')
      end
    end

  end

end

describe_pattern "CISCOFW305011", ['legacy', 'ecs-v1'] do

  let(:message) { "Built dynamic TCP translation from inside:172.31.98.44/1772 to outside:100.66.98.44/8256" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"172.31.98.44", "port"=>1772}
      expect(subject).to include "destination"=>{"ip"=>"100.66.98.44", "port"=>8256}
      expect(subject).to include "observer"=>{"ingress"=>{"interface"=>{"name"=>"inside"}}, "egress"=>{"interface"=>{"name"=>"outside"}}}
      expect(subject).to include "cisco"=>{"asa"=>{"network"=>{"transport"=>"TCP"}, "outcome"=>"Built"}}
    else
      expect(subject['src_ip']).to eq('172.31.98.44')
      expect(subject['src_xlated_ip']).to eq('100.66.98.44')
      expect(subject).to include "src_xlated_interface"=>"outside", "src_interface"=>"inside"
    end
  end

end

describe_pattern "CISCOFW313001_313004_313008", ['legacy', 'ecs-v1'] do

  let(:message) { "ASA-3-313001: Denied ICMP type=3, code=3 from 10.2.3.5 on interface Outside" }

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "source"=>{"ip"=>"10.2.3.5"}
      expect(subject).to include "cisco"=>{"asa"=>{"outcome"=>"Denied", "network"=>{"transport"=>"ICMP"}, "icmp_type"=>3, "icmp_code"=>3}}
    else
      expect(subject['src_ip']).to eq('10.2.3.5')
    end
  end

end

describe_pattern "CISCOFW313005", ['legacy', 'ecs-v1'] do

  let(:message) do
    "No matching connection for ICMP error message: icmp src fw111:10.192.33.100 dst fw111:192.18.4.1 (type 3, code 3) " +
        "on fw111 interface. Original IP payload: udp src 192.18.4.1/53 dst 8.8.8.8/10872."
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "event"=>{"reason"=>"No matching connection"}
      expect(subject).to include "source"=>{"ip"=>"10.192.33.100"}, "destination"=>{"ip"=>"192.18.4.1"}
      expect(subject).to include "observer"=>{"ingress"=>{"interface"=>{"name"=>"fw111"}}, "egress"=>{"interface"=>{"name"=>"fw111"}}}

      expect(subject).to include("cisco"=>{"asa"=>{
          "icmp_type"=>3, "icmp_code"=>3, "network"=>{"transport"=>"ICMP"},
          "original_ip_payload"=>{
              "destination"=>{"ip"=>"8.8.8.8", "port"=>10872},
              "network"=>{"transport"=>"udp"},
              "source"=>{"ip"=>"192.18.4.1", "port"=>53}
          }
      }})
    else
      # YAY, fails to match!
    end
  end

end

describe_pattern "CISCOFW402117", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-4-402117: IPSEC: Received a non-IPSec packet (protocol= ICMP) from 10.5.1.127 to 192.168.6.102."
  end

  include_examples 'top-level namespaces', ['cisco', 'source', 'destination'], if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("cisco"=>{"asa"=>{"network"=>{"transport"=>"ICMP", "type"=>"IPSEC"}}},
                                 "source"=>{"ip"=>"10.5.1.127"}, "destination"=>{"ip"=>"192.168.6.102"})

    else
      expect(subject).to include "src_ip"=>"10.5.1.127", "orig_protocol"=>"ICMP", "protocol"=>"IPSEC", "dst_ip"=>"192.168.6.102"
    end
  end

end

describe_pattern "CISCOFW402119", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-4-402119: IPSEC: Received an ESP packet (SPI= 0x1B86506B, sequence number= 0x28B) from 68.18.122.4 (user= Bangalo) to 10.10.1.1 that failed anti-replay checking."
  end

  include_examples 'top-level namespaces', ['cisco', 'source', 'destination'], if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "destination"=>{"ip"=>"10.10.1.1"},
                                 "cisco"=>{"asa"=>{
                                     "ipsec"=>{"spi"=>"0x1B86506B", "protocol"=>"ESP", "seq_num"=>"0x28B"},
                                     "network"=>{"type"=>"IPSEC"}
                                 }},
                                 "source"=>{"ip"=>"68.18.122.4", "user"=>{"name"=>"Bangalo"}}
    else
      expect(subject).to include "dst_ip"=>"10.10.1.1", "src_ip"=>"68.18.122.4",
                                 "spi"=>"0x1B86506B", "seq_num"=>"0x28B",
                                 "protocol"=>"IPSEC", "orig_protocol"=>"ESP",
                                 "user"=>"Bangalo"
    end
  end

end

describe_pattern "CISCOFW419001", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-4-419001: Dropping TCP packet from outside:65.55.184.155/80 to inside:192.168.10.11/49043, reason: MSS exceeded, MSS 1380, data 1460"
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("source"=>{"port"=>80, "ip"=>"65.55.184.155"},
                                 "destination"=>{"port"=>49043, "ip"=>"192.168.10.11"},
                                 "cisco"=>{"asa"=>{
                                     "outcome"=>"Dropping", "network"=>{"transport"=>"TCP"}
                                 }},
                                 "observer"=>{
                                     "ingress"=>{"interface"=>{"name"=>"outside"}},
                                     "egress"=>{"interface"=>{"name"=>"inside"}}
                                 })
      expect(subject).to include "event"=>{"reason"=>"MSS exceeded, MSS 1380, data 1460"}
    else
      expect(subject).to include "src_ip"=>"65.55.184.155", "src_port"=>"80", "src_interface"=>"outside",
                                 "dst_ip"=>"192.168.10.11", "dst_port"=>"49043", "dst_interface"=>"inside",
                                 "protocol"=>"TCP", "action"=>"Dropping",
                                 "reason"=>"MSS exceeded, MSS 1380, data 1460"
    end
  end

end

describe_pattern "CISCOFW419002", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-4-419002: Duplicate TCP SYN from OUTSIDE:10.10.66.2/65087 to INSIDE:10.10.1.6/443 with different initial sequence number."
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "event"=>{"reason"=>"Duplicate TCP SYN"},
                                 "source"=>{"port"=>65087, "ip"=>"10.10.66.2"},
                                 "destination"=>{"port"=>443, "ip"=>"10.10.1.6"},
                                 "observer"=>{"egress"=>{"interface"=>{"name"=>"INSIDE"}}, "ingress"=>{"interface"=>{"name"=>"OUTSIDE"}}}
    else
      expect(subject).to include "src_ip"=>"10.10.66.2", "src_port"=>"65087", "src_interface"=>"OUTSIDE",
                                 "dst_ip"=>"10.10.1.6", "dst_port"=>"443", "dst_interface"=>"INSIDE",
                                 "reason"=>"Duplicate TCP SYN"
    end
  end

end

describe_pattern "CISCOFW602303_602304", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-6-602303: IPSEC: An outbound LAN-to-LAN SA (SPI= 0xF81283) between 91.240.17.178 and 192.168.2.2 (user= admin) has been created."
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("cisco"=>{"asa"=>{
                                    "network"=>{"direction"=>"outbound", "type"=>"IPSEC"},
                                    "outcome"=>"created",
                                    "ipsec"=>{"spi"=>"0xF81283", "tunnel_type"=>"LAN-to-LAN"}}},
                                 "destination"=>{"ip"=>"192.168.2.2"},
                                 "source"=>{"ip"=>"91.240.17.178", "user"=>{"name"=>"admin"}})
    else
      expect(subject).to include "protocol"=>"IPSEC", "direction"=>"outbound", "tunnel_type"=>"LAN-to-LAN",
                                 "src_ip"=>"91.240.17.178", "dst_ip"=>"192.168.2.2",
                                 "spi"=>"0xF81283", "user"=>"admin", "action"=>"created"
    end
  end

end

describe_pattern "CISCOFW710001_710002_710003_710005_710006", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%PIX-7-710001: TCP access requested from 192.168.1.2/2354 to inside:192.168.1.1/443"
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("source"=>{"ip"=>"192.168.1.2", "port"=>2354})
      expect(subject).to include("destination"=>{"ip"=>"192.168.1.1", "port"=>443})
      expect(subject).to include("observer"=>{"egress"=>{"interface"=>{"name"=>"inside"}}},
                                 "cisco"=>{"asa"=>{"outcome"=>"requested", "network"=>{"transport"=>"TCP"}}})
    else
      expect(subject).to include "src_ip"=>"192.168.1.2", "src_port"=>"2354",
                                 "dst_ip"=>"192.168.1.1", "dst_port"=>"443", "dst_interface"=>"inside",
                                 "action"=>"requested"
    end
  end

end

describe_pattern "CISCOFW713172", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-6-713172: Group = 212.9.5.245, IP = 212.9.5.245, Automatic NAT Detection Status:    " +
        "Remote end is NOT behind a NAT device    This  end  IS  behind a NAT device"
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include("source"=>{"ip"=>"212.9.5.245"}, "cisco"=>{"asa"=>{"source"=>{"group"=>"212.9.5.245"}}})
      expect(event.get('@metadata')).to include "cisco"=>{"asa"=>{"local_nat"=>"IS", "remote_nat"=>"is NOT"}} # needs processing
    else
      expect(subject).to include("group"=>"212.9.5.245", "src_ip"=>"212.9.5.245",
                                 "is_local_natted"=>"IS", "is_remote_natted"=>"is NOT")
    end
  end

end

describe_pattern "CISCOFW733100", ['legacy', 'ecs-v1'] do

  let(:message) do
    "%ASA-4-733100: [192.168.2.2] drop rate-1 exceeded. Current burst rate is 0 per second, max configured rate is -4; " +
        "Current average rate is 7 per second, max configured rate is -5; Cumulative total count is 9063"
  end

  include_examples 'top-level namespaces', CISCOFW_ALLOWED_TOP_LEVEL_NAMESPACES, if: -> { ecs_compatibility? }

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include "cisco"=>{"asa"=>{"burst"=>{
                                    "object"=>"192.168.2.2", "id"=>"rate-1",
                                    "configured_rate"=>-4, "current_rate"=>0,
                                    "avg_rate"=>7, "configured_avg_rate"=>-5,
                                    "cumulative_count"=>9063}}}
    else
      expect(subject).to include "drop_type"=>"192.168.2.2", "drop_rate_id"=>"rate-1",
                                 "drop_rate_current_avg"=>"7",
                                 "drop_total_count"=>"9063",
                                 "drop_rate_current_burst"=>"0",
                                 "drop_rate_max_burst"=>"-4",
                                 "drop_rate_max_avg"=>"-5"
    end
  end

end

describe_pattern "CISCO_TAGGED_SYSLOG", ['legacy', 'ecs-v1'] do

  let(:message) { "<191>Jan 24 11:28:30.407: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to down" }

  it 'matches' do
    expect(subject).to include("timestamp"=>'Jan 24 11:28:30.407')
    if ecs_compatibility?
      expect(subject).to include('log' => {'syslog' => {'priority' => 191}})
      expect(subject).to include('cisco' => {'asa' => {'tag' => 'LINEPROTO-5-UPDOWN'}})
    else
      expect(subject).to include("syslog_pri"=>'191')
      expect(subject).to include("ciscotag"=>'LINEPROTO-5-UPDOWN')
    end
  end

  context 'with host' do

    let(:message) do
      '<191>Aug  1 14:01:20 abc-asa1: %ASA-6-302013: Built outbound TCP connection 906569140 for out-v1101:10.125.126.86/2010 (10.125.126.86/2010) to ent-v1124:100.100.100.111/51444 (10.125.1.11/37785)'
    end

    it 'matches' do
      expect(subject).to include("timestamp"=>'Aug  1 14:01:20')
      if ecs_compatibility?
        expect(subject).to include('log' => {'syslog' => {'priority' => 191}})
        expect(subject).to include('host' => {'hostname' => 'abc-asa1'})
        expect(subject).to include('cisco' => {'asa' => {'tag' => 'ASA-6-302013'}})
      else
        expect(subject).to include("syslog_pri"=>'191')
        expect(subject).to include("sysloghost"=>'abc-asa1')
        expect(subject).to include("ciscotag"=>'ASA-6-302013')
      end
    end

  end

end


describe_pattern 'SFW2', ['legacy', 'ecs-v1'] do

  let(:message) do
    "Jan 29 00:00:28 myth kernel: SFW2-INext-DROP-DEFLT IN=ppp0 OUT= MAC= SRC=24.64.208.134 DST=216.58.112.55 LEN=512 TOS=0x00 PREC=0x00 TTL=70 ID=55012 PROTO=UDP SPT=24128 DPT=1026 LEN=492"
  end

  it 'matches' do
    # NOTE: we do not match the second LEN=492 which is the length of the wrapped (UDP in this case) packet
    # iptables.length (IP packet length) 512 = 492 (UDP/TCP packet length) + 20 (IPv4 header length = 20 bytes)
    if ecs_compatibility?
      expect(grok).to include(
                          "timestamp"=>"Jan 29 00:00:28",
                          "observer"=>{"hostname"=>"myth", "ingress"=>{"interface"=>{"name"=>"ppp0"}}},
                          "suse"=>{"firewall"=>{"action"=>"DROP-DEFLT", "log_prefix"=>"SFW2-INext-DROP-DEFLT"}},
                          "source"=>{"ip"=>"24.64.208.134", "port"=>24128},
                          "destination"=>{"ip"=>"216.58.112.55", "port"=>1026},
                          "iptables"=>{
                              "length"=>512, # IP packet length
                              "id"=>"55012",
                              "ttl"=>70,
                              "tos"=>"00",
                              "precedence_bits"=>"00"
                          },
                          "network"=>{"transport"=>"UDP"}
                      )
    else
      expect(grok).to include(
                          "nf_action"=>"DROP-DEFLT",
                          "nf_in_interface"=>"ppp0",
                          "nf_src_ip"=>"24.64.208.134",
                          "nf_dst_ip"=>"216.58.112.55",
                          "nf_protocol"=>"UDP"
                          )
    end
  end

  context 'long message' do

    let(:message) do
      'Mar  8 20:16:44 black kernel: [20474.050964] SFW2-INext-ACC-TCP IN=eth0 OUT= MAC=28:45:a7:f3:18:00:00:22:15:67:6a:25:08:00 SRC=192.168.0.101 DST=192.168.0.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=6429 DF PROTO=TCP SPT=59282 DPT=631 WINDOW=14600 RES=0x00 SYN URGP=0 OPT (020405B40402080A00825F5D0000000001030307)'
    end

    it 'matches' do
      if ecs_compatibility?
        expect(grok).to include(
                            "timestamp"=>"Mar  8 20:16:44",
                            "observer"=>{"hostname"=>"black", "ingress"=>{"interface"=>{"name"=>"eth0"}}},
                            "suse"=>{"firewall"=>{"action"=>"ACC-TCP", "log_prefix"=>"SFW2-INext-ACC-TCP"}},
                            "source"=>{"mac"=>"00:22:15:67:6a:25", "ip"=>"192.168.0.101", "port"=>59282},
                            "destination"=>{"mac"=>"28:45:a7:f3:18:00", "ip"=>"192.168.0.100", "port"=>631},
                            "iptables"=>{
                                "length"=>60,
                                "id"=>"6429",
                                "tos"=>"00", "fragment_flags"=>"DF",
                                "ttl"=>64,
                                "precedence_bits"=>"00",
                                "tcp"=>{"flags"=>"SYN ", "window"=>14600},
                                "tcp_reserved_bits"=>"00"
                            },
                            "network"=>{"transport"=>"TCP"}
                        )
      else
        expect(grok).to include(
                            "nagios_epoch"=>"20474.050964", # YAY!
                            "nf_action"=>"ACC-TCP",
                            "nf_in_interface"=>"eth0",
                            "nf_dst_port"=>"631",

                            "nf_dst_mac"=>"28:45:a7:f3:18:00",
                            "nf_src_mac"=>"00:22:15:67:6a:25",
                            "nf_dst_ip"=>"192.168.0.100",
                            "nf_src_ip"=>"192.168.0.101",
                            "nf_src_port"=>"59282",

                            "nf_protocol"=>"TCP"
                        )
      end
    end

  end

  context 'alternate log-prefixes' do

    describe 'SuSE-FW-DROP-DEFAULT' do # by default we only match SFW2-INext-*

      let(:message) do
        "Mar 8 22:35:42 linux kernel: SuSE-FW-DROP-DEFAULT IN=ppp0 OUT= MAC= SRC=202.175.181.4 DST=64.238.136.187 LEN=48 TOS=0x00 PREC=0x00 TTL=113 ID=31151 DF PROTO=TCP SPT=3360 DPT=3127 WINDOW=65340 RES=0x00 SYN URGP=0 OPT (020405AC01010402)"
      end

      it 'does not match' do
        expect(grok['tags']).to include('_grokparsefailure')
      end

    end

    describe 'SFW2-IN-ACC-RELATED' do

      let(:message) do
        "Jan 15 11:21:13 IKCSWeb kernel: SFW2-IN-ACC-RELATED IN=eth1 OUT= MAC=00:19:bb:2e:85:42:00:17:c5:d8:2e:2c:08:00 SRC=59.64.166.81 DST=207.194.99.122 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=48949 DF PROTO=TCP SPT=24093 DPT=22 WINDOW=137 RES=0x00 ACK URGP=0"
      end

      it 'does not match' do
        expect(grok['tags']).to include('_grokparsefailure')
      end

    end

  end

  context 'IPv6 message' do

    let(:message) do
      "Jan 15 11:21:13 IKCS-Web kernel: SFW2-INext-ACC-RELATED IN=eth0 OUT=eth1 MAC= SRC=fe80:0000:0000:0000:16da:e9ff:feec:a04d DST=ff02:0000:0000:0000:0000:0000:0000:00fb LEN=527 TC=0 HOPLIMIT=255 FLOWLBL=804001 PROTO=UDP SPT=5353 DPT=5353 LEN=487"
    end

    it 'matches' do
      if ecs_compatibility?
        iptables = grok['iptables']
        expect(iptables).to include("flow_label"=>"804001")
        expect(iptables['ttl'].to_s).to eql('255')
        expect(iptables['length'].to_s).to eql('527')
        expect(grok).to include("observer"=>{"hostname"=>"IKCS-Web", "ingress"=>{"interface"=>{"name"=>"eth0"}}, "egress"=>{"interface"=>{"name"=>"eth1"}}})
        expect(grok).to include(
                            "source"=>{"ip"=>"fe80:0000:0000:0000:16da:e9ff:feec:a04d", "port"=>5353},
                            "destination"=>{"ip"=>"ff02:0000:0000:0000:0000:0000:0000:00fb", "port"=>5353},
                            "network"=>{"transport"=>"UDP"}
                        )
        pending
        # TODO hitting a grok type-casting issue https://github.com/logstash-plugins/logstash-filter-grok/issues/165
        expect(iptables).to include("ttl"=>255, "flow_label"=>"804001", "length"=>527)
      else
        expect(grok).to include("nf_src_ip"=>"fe80:0000:0000:0000:16da:e9ff:feec:a04d",
                                "nf_dst_ip"=>"ff02:0000:0000:0000:0000:0000:0000:00fb",
                                "nf_protocol"=>"UDP")
      end
    end

  end

end

