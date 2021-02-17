# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

# NOTE: we only support non-structured log formats for all RT_FLOW_

describe_pattern "RT_FLOW1", ['legacy', 'ecs-v1'] do

  let(:message) do
    'Dec 17 08:05:30 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 10.10.10.2/53836->10.10.10.1/22 junos-ssh' +
    ' 10.10.10.2/53836->10.10.10.1/22 None None 6 log-host-traffic untrust junos-host 5 78(6657) 122(13305) 45' +
    ' UNKNOWN UNKNOWN N/A(N/A) ge-0/0/1.0 No '
  end

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include(
                             "source"=>{"ip"=>"10.10.10.2", "port"=>53836, "nat"=>{"ip"=>"10.10.10.2", "port"=>53836}, "bytes"=>6657},
                             "destination"=>{"ip"=>"10.10.10.1", "port"=>22, "nat"=>{"ip"=>"10.10.10.1", "port"=>22}, "bytes"=>13305},
                             "observer"=>{"egress"=>{"zone"=>"junos-host"}, "ingress"=>{"zone"=>"untrust"}},
                             "rule"=>{"name"=>"log-host-traffic"},
                             "network"=>{"iana_number"=>"6"},
                             "juniper"=>{"srx"=>{
                                 "tag"=>"RT_FLOW_SESSION_CLOSE", "reason"=>"session closed TCP FIN",
                                 "session_id"=>"5", "service_name"=>"junos-ssh", "elapsed_time"=>45
                             }}
                         )
    else
      should include("event"=>"RT_FLOW_SESSION_CLOSE", "close-reason"=>"session closed TCP FIN",
                     "src-ip"=>"10.10.10.2", "src-port"=>"53836", "nat-src-ip"=>"10.10.10.2", "nat-src-port"=>"53836",
                     "dst-ip"=>"10.10.10.1", "dst-port"=>"22", "nat-dst-ip"=>"10.10.10.1", "nat-dst-port"=>"22",
                     "src-nat-rule-name"=>"None", "dst-nat-rule-name"=>"None",
                     "protocol-id"=>"6", "policy-name"=>"log-host-traffic",
                     "from-zone"=>"untrust", "to-zone"=>"junos-host",
                     "service"=>"junos-ssh", "session-id"=>"5",
                     "sent"=>"6657", "received"=>"13305", "elapsed-time"=>"45")
    end
  end

end

describe_pattern "RT_FLOW2", ['legacy', 'ecs-v1'] do

  let(:message) do
    'Dec 17 08:04:45 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.10.10.2/53836->10.10.10.1/22' +
    ' junos-ssh 10.10.10.2/53836->10.10.10.1/22 None None 6 log-host-traffic untrust junos-host 5 N/A(N/A) ge-0/0/1.0'
  end

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include(
                             "source"=>{"ip"=>"10.10.10.2", "port"=>53836, "nat"=>{"ip"=>"10.10.10.2", "port"=>53836}},
                             "destination"=>{"ip" => "10.10.10.1", "port"=>22, "nat"=>{"ip"=>"10.10.10.1", "port"=>22}},
                             "observer"=>{"ingress"=>{"zone"=>"untrust"}, "egress"=>{"zone"=>"junos-host"}},
                             "network"=>{"iana_number"=>"6"},
                             "juniper"=>{"srx"=>{"service_name"=>"junos-ssh", "session_id"=>"5", "tag"=>"RT_FLOW_SESSION_CREATE"}},
                             "rule"=>{"name"=>"log-host-traffic"}
                         )
    else
      should include("event"=>"RT_FLOW_SESSION_CREATE",
                     "src-ip"=>"10.10.10.2", "src-port"=>"53836",
                     "dst-ip"=>"10.10.10.1", "dst-port"=>"22",
                     "service"=>"junos-ssh",
                     "nat-src-ip"=>"10.10.10.2", "nat-src-port"=>"53836",
                     "nat-dst-ip"=>"10.10.10.1", "nat-dst-port"=>"22",
                     "src-nat-rule-name"=>"None", "dst-nat-rule-name"=>"None",
                     "protocol-id"=>"6",
                     "policy-name"=>"log-host-traffic",
                     "from-zone"=>"untrust", "to-zone"=>"junos-host",
                     "session-id"=>"5")
    end
  end

end

describe_pattern "RT_FLOW3", ['legacy', 'ecs-v1'] do

  let(:message) do
    'Sep 29 23:49:20 SRX-1 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.0.0.1/54924->192.168.1.1/53 junos-dns-udp ' +
        '17(0) default-deny(global) trust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 UNKNOWN policy deny'
  end

  it 'matches' do
    if ecs_compatibility?
      expect(subject).to include(
                             "source"=>{"ip"=>"10.0.0.1", "port"=>54924},
                             "destination"=>{"ip"=>"192.168.1.1", "port"=>53},
                             "juniper"=>{"srx"=>{"service_name"=>"junos-dns-udp", "tag"=>"RT_FLOW_SESSION_DENY"}},
                             "network"=>{"iana_number"=>"17"},
                             "observer"=>{"egress"=>{"zone"=>"trust"}, "ingress"=>{"zone"=>"trust"}},
                             "rule"=>{"name"=>"default-deny(global)"}
                         )
    else
      should include("event"=>"RT_FLOW_SESSION_DENY",
                     "src-ip"=>"10.0.0.1", "dst-ip"=>"192.168.1.1", "src-port"=>"54924", "dst-port"=>"53",
                     "protocol-id"=>"17", "from-zone"=>"trust", "to-zone"=>"trust",
                     "service"=>"junos-dns-udp", "policy-name"=>"default-deny(global)")
    end
  end

end
