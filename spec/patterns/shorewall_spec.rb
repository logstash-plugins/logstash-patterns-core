# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "SHOREWALL", ['legacy', 'ecs-v1'] do

  context "parsing a message with OUT interface" do

    let(:message) do
      "May 28 17:23:25 myHost kernel: [3124658.791874] Shorewall:FORWARD:REJECT:" +
      "IN=eth2 OUT=eth2 SRC=1.2.3.4 DST=192.168.0.10 LEN=141 TOS=0x00 PREC=0x00 TTL=63 ID=55251 PROTO=UDP SPT=5353 DPT=5335 LEN=121"
    end

    it 'matches' do
      expect(subject).to include("timestamp" => "May 28 17:23:25")
      if ecs_compatibility?
        expect(subject).to include(
                            "observer"=>{"hostname"=>"myHost", "ingress"=>{"interface"=>{"name"=>"eth2"}}, "egress"=>{"interface"=>{"name"=>"eth2"}}},
                            "shorewall"=>{'firewall'=>{"type"=>"FORWARD", "action"=>"REJECT"}},
                            "iptables"=>{
                                "length"=>141,
                                "tos"=>"00", "precedence_bits"=>"00",
                                "ttl"=>63,
                                "id"=>"55251"
                            },
                            "network"=>{"transport"=>"UDP"},
                            "source"=>{"ip"=>"1.2.3.4", "port"=>5353},
                            "destination"=>{"ip"=>"192.168.0.10", "port"=>5335}
                        )
      else
        expect(subject).to include("nf_host" => "myHost")
        expect(subject).to include("nf_action1" => "FORWARD")
        expect(subject).to include("nf_action2" => "REJECT")
        expect(subject).to include("nf_in_interface" => "eth2")
        expect(subject).to include("nf_out_interface" => "eth2")
        expect(subject).to include("nf_src_ip" => "1.2.3.4")
        expect(subject).to include("nf_dst_ip" => "192.168.0.10")
        expect(subject).to include("nf_len" => "141")
        expect(subject).to include("nf_tos" => "0x00")
        expect(subject).to include("nf_prec" => "0x00")
        expect(subject).to include("nf_ttl" => "63")
        expect(subject).to include("nf_id" => "55251")
        expect(subject).to include("nf_protocol" => "UDP")
        expect(subject).to include("nf_src_port" => "5353")
        expect(subject).to include("nf_dst_port" => "5335")
      end
    end

  end

  context "parsing a message without OUT interface" do


    let(:message) do
      "May 28 17:31:07 server Shorewall:net2fw:DROP:" +
      "IN=eth1 OUT= MAC=00:02:b3:c7:2f:77:38:72:c0:6e:92:9c:08:00 SRC=127.0.0.1 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=6480 DF PROTO=TCP SPT=59088 DPT=8080 WINDOW=2920 RES=0x00 SYN URGP=0"
    end

    it 'matches' do
      expect(subject).to include("timestamp" => "May 28 17:31:07")
      if ecs_compatibility?
        expect(subject).to include(
                            "observer"=>{"hostname"=>"server", "ingress"=>{"interface"=>{"name"=>"eth1"}}}, # no "output_interface"
                            "shorewall"=>{'firewall'=>{"type"=>"net2fw", "action"=>"DROP",}},
                            "iptables"=>{
                                "length"=>60,
                                "tos"=>"00", "precedence_bits"=>"00",
                                "ttl"=>49,
                                "id"=>"6480",

                                "fragment_flags"=>"DF",
                                "tcp"=>{"flags"=>"SYN ", "window"=>2920},
                                "tcp_reserved_bits"=>"00",
                            },
                            "network"=>{"transport"=>"TCP"}
                        )
        expect(subject).to include("source"=>{"ip"=>"127.0.0.1", "port"=>59088, 'mac'=>"38:72:c0:6e:92:9c"})
        expect(subject).to include("destination"=>{"ip"=>"1.2.3.4", "port"=>8080, 'mac'=>"00:02:b3:c7:2f:77"})
      else
        expect(subject).to include("nf_host" => "server")
        expect(subject).to include("nf_action1" => "net2fw")
        expect(subject).to include("nf_action2" => "DROP")
        expect(subject).to include("nf_in_interface" => "eth1")
        expect(subject["nf_out_interface"]).to be nil
        expect(subject).to include("nf_dst_mac" => "00:02:b3:c7:2f:77")
        expect(subject).to include("nf_src_mac" => "38:72:c0:6e:92:9c")
        expect(subject).to include("nf_src_ip" => "127.0.0.1")
        expect(subject).to include("nf_dst_ip" => "1.2.3.4")
        expect(subject).to include("nf_len" => "60")
        expect(subject).to include("nf_tos" => "0x00")
        expect(subject).to include("nf_prec" => "0x00")
        expect(subject).to include("nf_ttl" => "49")
        expect(subject).to include("nf_id" => "6480")
        expect(subject).to include("nf_protocol" => "TCP")
        expect(subject).to include("nf_src_port" => "59088")
        expect(subject).to include("nf_dst_port" => "8080")
      end
    end

  end
end
