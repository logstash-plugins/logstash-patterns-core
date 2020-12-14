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
                          "observer"=>{"hostname"=>"myth"},
                          "suse"=>{"firewall"=>{"action"=>"DROP-DEFLT", "log_prefix"=>"SFW2-INext-DROP-DEFLT"}},
                          "source"=>{"ip"=>"24.64.208.134", "port"=>24128},
                          "destination"=>{"ip"=>"216.58.112.55", "port"=>1026},
                          "iptables"=>{
                              "input_interface"=>"ppp0",
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
                            "observer"=>{"hostname"=>"black"},
                            "suse"=>{"firewall"=>{"action"=>"ACC-TCP", "log_prefix"=>"SFW2-INext-ACC-TCP"}},
                            "source"=>{"mac"=>"00:22:15:67:6a:25", "ip"=>"192.168.0.101", "port"=>59282},
                            "destination"=>{"mac"=>"28:45:a7:f3:18:00", "ip"=>"192.168.0.100", "port"=>631},
                            "iptables"=>{
                                "input_interface"=>"eth0",
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
      "Jan 15 11:21:13 IKCSWeb kernel: SFW2-INext-ACC-RELATED IN=eth0 OUT= MAC= SRC=fe80:0000:0000:0000:16da:e9ff:feec:a04d DST=ff02:0000:0000:0000:0000:0000:0000:00fb LEN=527 TC=0 HOPLIMIT=255 FLOWLBL=804001 PROTO=UDP SPT=5353 DPT=5353 LEN=487"
    end

    it 'matches' do
      if ecs_compatibility?
        iptables = grok['iptables']
        expect(iptables).to include("input_interface"=>"eth0", "flow_label"=>"804001")
        expect(iptables['ttl'].to_s).to eql('255')
        expect(iptables['length'].to_s).to eql('527')
        expect(grok).to include(
                            "source"=>{"ip"=>"fe80:0000:0000:0000:16da:e9ff:feec:a04d", "port"=>5353},
                            "destination"=>{"ip"=>"ff02:0000:0000:0000:0000:0000:0000:00fb", "port"=>5353},
                            "network"=>{"transport"=>"UDP"}
                        )
        pending
        # TODO hitting a grok type-casting issue https://github.com/logstash-plugins/logstash-filter-grok/issues/165
        expect(iptables).to include("input_interface"=>"eth0", "ttl"=>255, "flow_label"=>"804001", "length"=>527)
      else
        expect(grok).to include("nf_src_ip"=>"fe80:0000:0000:0000:16da:e9ff:feec:a04d",
                                "nf_dst_ip"=>"ff02:0000:0000:0000:0000:0000:0000:00fb",
                                "nf_protocol"=>"UDP")
      end
    end

  end

end

