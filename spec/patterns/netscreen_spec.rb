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
        expect(subject).to include("timestamp" => "Jun  2 14:53:31")
        expect(subject).to include("netscreen"=>{
            "session"=>{"id"=>"488451", "start_time"=>"2015-11-11 10:02:10", "duration"=>0, "type"=>"traffic", "reason"=>"Creation"},
            "policy_id"=>"244", "service"=>"https", "protocol_number"=>6, "device_id"=>"0000011001000011"
        })
        expect(subject).to include("event"=>{"code"=>"00257", "action"=>"Permit"})
        # expect(subject).to include("network"=>{"protocol"=>"https"})
        expect(subject).to include("source"=>{"bytes"=>0, "nat"=>{"port"=>22041, "ip"=>"1.255.20.1"}, "port"=>1732, "address"=>"74.168.138.252"})
        expect(subject).to include("destination"=>{"bytes"=>0, "nat"=>{"port"=>443, "ip"=>"1.244.136.50"}, "port"=>443, "address"=>"72.72.72.72"})
        expect(subject).to include("observer"=>{
            "ingress"=>{"zone"=>"Untrust"}, "hostname"=>"sample-host", "name"=>"isg1000-A2", "product"=>"NetScreen",
            "egress"=>{"zone"=>"Trust"}
        })
      else
        expect(subject).to include("date" => "Jun  2 14:53:31")
        expect(subject).to include(
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

  context "traffic denied (without port/xlated/session_id/reason suffix)" do

    let(:message) do
      'Mar 18 17:56:52 192.168.56.11 lowly_lizard: NetScreen device_id=netscreen2 [Root]system-notification-00257(traffic): ' +
          'start_time="2009-03-18 16:07:06" duration=0 policy_id=320001 service=msrpc Endpoint Mapper(tcp) proto=6 ' +
          'src zone=Null dst zone=self action=Deny sent=0 rcvd=16384 src=21.10.90.125 dst=23.16.1.1'
    end

    it 'matches in ECS mode' do
      if ecs_compatibility?
        expect(subject).to include("timestamp" => "Mar 18 17:56:52")
        expect(subject).to include("netscreen"=>{
            "device_id"=>"netscreen2",
            "policy_id"=>"320001",
            "service"=>"msrpc Endpoint Mapper(tcp)",
            "protocol_number"=>6,
            "session"=>{"start_time"=>"2009-03-18 16:07:06", "type"=>"traffic", "duration"=>0}
        })
        expect(subject).to include("source"=>{"address"=>"21.10.90.125", "bytes"=>0})
        expect(subject).to include("destination"=>{"address"=>"23.16.1.1", "bytes"=>16384})
      else
        expect(grok['tags']).to include('_grokparsefailure')
      end
    end
  end

  context "'standard' traffic denied" do

    let(:message) do
      'Jun  2 14:53:31 fire00 aka1: NetScreen device_id=aka1  [Root]system-notification-00257(traffic): start_time="2006-06-02 14:53:30" ' +
          'duration=0 policy_id=120 service=udp/port:17210 proto=17 src zone=Trust dst zone=DMZ action=Deny sent=0 rcvd=0 ' +
          'src=192.168.2.2 dst=1.2.3.4 src_port=53 dst_port=17210'
    end

    it 'matches (in ECS mode)' do
      if ecs_compatibility?
        expect(subject).to include("event"=>{"action"=>"Deny", "code"=>"00257"})
      else
        expect(grok['tags']).to include('_grokparsefailure')
        expect(subject).to_not include("date" => "Jun  2 14:53:31")
      end
    end

    context "(with session id)" do

      let(:message) do
        super + ' session_id=0 reason=Traffic Denied'
      end

      it 'matches (in ECS mode)' do
        if ecs_compatibility?
          expect(subject).to include("netscreen"=>hash_including("device_id"=>"aka1", "service"=>"udp/port:17210",
                                     "session"=>hash_including("reason"=>"Traffic Denied")))
          expect(subject).to include("observer"=>{
              "ingress"=>{"zone"=>"Trust"},
              "egress"=>{"zone"=>"DMZ"}, "hostname"=>"fire00", "name"=>"aka1",
              "product"=>"NetScreen"
          })
        else
          expect(grok['tags']).to include('_grokparsefailure')
          expect(subject).to_not include("date" => "Jun  2 14:53:31")
        end
      end

    end

  end

end
