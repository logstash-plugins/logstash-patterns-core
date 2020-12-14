# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "NETSCREENSESSIONLOG", ['legacy', 'ecs-v1'] do

  context "sample traffic denied" do

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
