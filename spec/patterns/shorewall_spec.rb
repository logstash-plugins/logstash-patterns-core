# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "SHOREWALL" do

  let(:pattern)    { "SHOREWALL" }

  context "parsing a message with OUT interface" do

    let(:value) { "May 28 17:23:25 myHost kernel: [3124658.791874] Shorewall:FORWARD:REJECT:IN=eth2 OUT=eth2 SRC=1.2.3.4 DST=1.2.3.4 LEN=141 TOS=0x00 PREC=0x00 TTL=63 ID=55251 PROTO=UDP SPT=5353 DPT=5353 LEN=121" }

    subject     { grok_match(pattern, value) }

    it { should include("timestamp" => "May 28 17:23:25") }

    it { should include("nf_host" => "myHost") }

    it { should include("nf_action1" => "FORWARD") }

    it { should include("nf_action2" => "REJECT") }

    it { should include("nf_in_interface" => "eth2") }

    it { should include("nf_out_interface" => "eth2") }

    it { should include("nf_src_ip" => "1.2.3.4") }

    it { should include("nf_dst_ip" => "1.2.3.4") }

    it { should include("nf_len" => "141") }

    it { should include("nf_tos" => "0x00") }

    it { should include("nf_prec" => "0x00") }

    it { should include("nf_ttl" => "63") }

    it { should include("nf_id" => "55251") }

    it { should include("nf_protocol" => "UDP") }

    it { should include("nf_src_port" => "5353") }

    it { should include("nf_dst_port" => "5353") }
  end

  context "parsing a message without OUT interface" do

    let(:value) { "May 28 17:31:07 myHost kernel: [3125121.106700] Shorewall:net2fw:DROP:IN=eth1 OUT= MAC=00:02:b3:c7:2f:77:38:72:c0:6e:92:9c:08:00 SRC=1.2.3.4 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=6480 DF PROTO=TCP SPT=59088 DPT=8080 WINDOW=2920 RES=0x00 SYN URGP=0" }

    subject     { grok_match(pattern, value) }

    it { should include("timestamp" => "May 28 17:31:07") }

    it { should include("nf_host" => "myHost") }

    it { should include("nf_action1" => "net2fw") }

    it { should include("nf_action2" => "DROP") }

    it { should include("nf_in_interface" => "eth1") }

    it { expect(subject["nf_out_interface"]).to be_nil }

    it { should include("nf_dst_mac" => "00:02:b3:c7:2f:77") }

    it { should include("nf_src_mac" => "38:72:c0:6e:92:9c") }

    it { should include("nf_src_ip" => "1.2.3.4") }

    it { should include("nf_dst_ip" => "1.2.3.4") }

    it { should include("nf_len" => "60") }

    it { should include("nf_tos" => "0x00") }

    it { should include("nf_prec" => "0x00") }

    it { should include("nf_ttl" => "49") }

    it { should include("nf_id" => "6480") }

    it { should include("nf_protocol" => "TCP") }

    it { should include("nf_src_port" => "59088") }

    it { should include("nf_dst_port" => "8080") }
  end
end
