# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "NETSCREENSESSIONLOG", ['legacy', 'ecs-v1'] do

  context "traffic denied (Juniper)" do

    let(:message) do
      'Jun  2 14:53:31 sample-host isg1000-A2: NetScreen device_id=0000011001000011 [Root]system-notification-00257(traffic): ' +
          'start_time="2015-11-11 10:02:10" duration=0 policy_id=244 service=https proto=6 src zone=Untrust dst zone=Trust ' +
          'action=Permit sent=0 rcvd=0 src=74.168.138.252 dst=72.72.72.72 src_port=1732 dst_port=443 ' +
          'src-xlated ip=1.255.20.1 port=22041 dst-xlated ip=1.244.136.50 port=443 session_id=488451 reason=Creation'
    end

    it 'matches' do
      if ecs_compatibility?
        should include("timestamp" => "Jun  2 14:53:31")
        should include("netscreen"=>{
            "session"=>{"id"=>"488451", "start_time"=>"2015-11-11 10:02:10", "duration"=>0, "type"=>"traffic", "reason"=>"Creation"},
            "policy_id"=>"244", "service"=>"https", "protocol_number"=>6, "device_id"=>"0000011001000011"
        })
        should include("event"=>{"code"=>"00257", "action"=>"Permit"})
        # should include("network"=>{"protocol"=>"https"})
        should include("source"=>{"bytes"=>0, "nat"=>{"port"=>22041, "ip"=>"1.255.20.1"}, "port"=>1732, "address"=>"74.168.138.252"})
        should include("destination"=>{"bytes"=>0, "nat"=>{"port"=>443, "ip"=>"1.244.136.50"}, "port"=>443, "address"=>"72.72.72.72"})
        should include("observer"=>{
            "ingress"=>{"zone"=>"Untrust"}, "hostname"=>"sample-host", "name"=>"isg1000-A2", "product"=>"NetScreen",
            "egress"=>{"zone"=>"Trust"}
        })
      else
        should include("date" => "Jun  2 14:53:31")
        should include(
                   "device"=>"sample-host",
                   "device_id"=>"0000011001000011",
                   "start_time"=>"\"2015-11-11 10:02:10\"",
                   "duration"=>"0",
                   "policy_id"=>"244",
                   "service"=>"https",
                   "proto"=>"6",
                   "src_zone"=>"Untrust", "dst_zone"=>"Trust",
                   "action"=>"Permit",
                   "sent"=>"0", "rcvd"=>"0",
                   "src_ip"=>"74.168.138.252", "dst_ip"=>"72.72.72.72",
                   "src_port"=>"1732", "dst_port"=>"443",
                   "src_xlated_ip"=>"1.255.20.1", "src_xlated_port"=>"22041",
                   "dst_xlated_ip"=>"1.244.136.50", "dst_xlated_port"=>"443",
                   "session_id"=>"488451", "reason"=>"Creation",
                   )
      end
    end

  end

  context "'standard' traffic denied" do

    let(:message) do
      'Jun  2 14:53:31 fire00 aka1: NetScreen device_id=aka1  [Root]system-notification-00257(traffic): start_time="2006-06-02 14:53:30" ' +
          'duration=0 policy_id=120 service=udp/port:17210 proto=17 src zone=Trust dst zone=DMZ action=Deny sent=0 rcvd=0 ' +
          'src=192.168.2.2 dst=1.2.3.4 src_port=53 dst_port=17210'
    end

    it 'does not match' do # NOTE: matching could/should be fixed - this is of a current state of affairs
      expect(grok['tags']).to include('_grokparsefailure')
      if ecs_compatibility?
        # no-op
      else
        should_not include("date" => "Jun  2 14:53:31")
      end
    end

    context "(with session id)" do

      let(:message) do
        super + ' session_id=0 reason=Traffic Denied'
      end

      it 'does not match' do # NOTE: matching could/should be fixed - this is of a current state of affairs
        expect(grok['tags']).to include('_grokparsefailure')
        if ecs_compatibility?
          # no-op
        else
          should_not include("date" => "Jun  2 14:53:31")
        end
      end

    end

  end

end
