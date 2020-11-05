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
      should include("timestamp" => "May 28 17:23:25")

      if ecs_compatibility?
        expect(grok).to include(
                            "host"=>{"hostname"=>"myHost"},
                            "shorewall"=>{'firewall'=>{"type"=>"FORWARD", "action"=>"REJECT"}},
                            "iptables"=>{
                                "input_interface"=>"eth2", "output_interface"=>"eth2",
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
        should include("nf_host" => "myHost")
        should include("nf_action1" => "FORWARD")
        should include("nf_action2" => "REJECT")
        should include("nf_in_interface" => "eth2")
        should include("nf_out_interface" => "eth2")
        should include("nf_src_ip" => "1.2.3.4")
        should include("nf_dst_ip" => "192.168.0.10")
        should include("nf_len" => "141")
        should include("nf_tos" => "0x00")
        should include("nf_prec" => "0x00")
        should include("nf_ttl" => "63")
        should include("nf_id" => "55251")
        should include("nf_protocol" => "UDP")
        should include("nf_src_port" => "5353")
        should include("nf_dst_port" => "5335")
      end
    end

  end

  context "parsing a message without OUT interface" do


    let(:message) do
      "May 28 17:31:07 server Shorewall:net2fw:DROP:" +
      "IN=eth1 OUT= MAC=00:02:b3:c7:2f:77:38:72:c0:6e:92:9c:08:00 SRC=127.0.0.1 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=6480 DF PROTO=TCP SPT=59088 DPT=8080 WINDOW=2920 RES=0x00 SYN URGP=0"
    end

    it 'matches' do
      should include("timestamp" => "May 28 17:31:07")
      if ecs_compatibility?
        expect(grok).to include(
                            "host"=>{"hostname"=>"server"},
                            "shorewall"=>{'firewall'=>{"type"=>"net2fw", "action"=>"DROP",}},
                            "iptables"=>{
                                "input_interface"=>"eth1", # no "output_interface"
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
        expect(grok).to include("source"=>{"ip"=>"127.0.0.1", "port"=>59088, 'mac'=>"38:72:c0:6e:92:9c"})
        expect(grok).to include("destination"=>{"ip"=>"1.2.3.4", "port"=>8080, 'mac'=>"00:02:b3:c7:2f:77"})
      else
        should include("nf_host" => "server")
        should include("nf_action1" => "net2fw")
        should include("nf_action2" => "DROP")
        should include("nf_in_interface" => "eth1")
        expect(subject["nf_out_interface"]).to be nil
        should include("nf_dst_mac" => "00:02:b3:c7:2f:77")
        should include("nf_src_mac" => "38:72:c0:6e:92:9c")
        should include("nf_src_ip" => "127.0.0.1")
        should include("nf_dst_ip" => "1.2.3.4")
        should include("nf_len" => "60")
        should include("nf_tos" => "0x00")
        should include("nf_prec" => "0x00")
        should include("nf_ttl" => "49")
        should include("nf_id" => "6480")
        should include("nf_protocol" => "TCP")
        should include("nf_src_port" => "59088")
        should include("nf_dst_port" => "8080")
      end
    end

  end
end
