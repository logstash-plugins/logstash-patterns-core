# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "NAGIOSLOGLINE - CURRENT HOST STATE" do

  let(:value)   { "[1427925600] CURRENT HOST STATE: nagioshost;UP;HARD;1;PING OK - Packet loss = 0%, RTA = 2.24 ms" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => 1427925600)
  end

  it "generates the nagios_message field" do
    expect(grok).to include("nagios_message" => "PING OK - Packet loss = 0%, RTA = 2.24 ms")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_state field" do
    expect(grok).to include("nagios_state" => "UP")
  end

  it "generates the nagios_statetype field" do
    expect(grok).to include("nagios_statetype" => "HARD")
  end

end

describe "NAGIOSLOGLINE - CURRENT SERVICE STATE" do

  let(:value)   { "[1427925600] CURRENT SERVICE STATE: nagioshost;nagiosservice;OK;HARD;1;nagiosmessage" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "CURRENT SERVICE STATE")
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => 1427925600)
  end

  it "generates the nagios_message field" do
    expect(grok).to include("nagios_message" => "nagiosmessage")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_service field" do
    expect(grok).to include("nagios_service" => "nagiosservice")
  end

  it "generates the nagios_state field" do
    expect(grok).to include("nagios_state" => "OK")
  end

  it "generates the nagios_statetype field" do
    expect(grok).to include("nagios_statetype" => "HARD")
  end

end

describe "NAGIOSLOGLINE - TIMEPERIOD TRANSITION" do

  let(:value)   { "[1427925600] TIMEPERIOD TRANSITION: 24X7;1;1" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "TIMEPERIOD TRANSITION")
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => 1427925600)
  end

  it "generates the nagios_esrvice field" do
    expect(grok).to include("nagios_service" => "24X7")
  end

  # Regression test for but fixed in Nagios patterns #30
  it "doesn't end in a semi-colon" do
    expect(grok['message']).to_not end_with(";")
  end

end

describe "NAGIOSLOGLINE - SERVICE ALERT" do

  let(:value)   { "[1427925689] SERVICE ALERT: varnish;Varnish Backend Connections;CRITICAL;SOFT;1;Current value: 154.0, warn threshold: 10.0, crit threshold: 20.0" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "SERVICE ALERT")
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => 1427925689)
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "varnish")
  end

  it "generates the nagios_service field" do
    expect(grok).to include("nagios_service" => "Varnish Backend Connections")
  end

  it "generates the nagios_state field" do
    expect(grok).to include("nagios_state" => "CRITICAL")
  end

  it "generates the nagios_statelevel field" do
    expect(grok).to include("nagios_statelevel" => "SOFT")
  end

  it "generates the nagios_message field" do
    expect(grok).to include("nagios_message" => "Current value: 154.0, warn threshold: 10.0, crit threshold: 20.0")
  end

end

describe "NAGIOSLOGLINE - SERVICE NOTIFICATION" do

  let(:value)   { "[1427950229] SERVICE NOTIFICATION: nagiosadmin;varnish;Varnish Backend Connections;CRITICAL;notify-service-by-email;Current value: 337.0, warn threshold: 10.0, crit threshold: 20.0" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "SERVICE NOTIFICATION")
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => 1427950229)
  end

  it "generates the nagios_notifyname field" do
    expect(grok).to include("nagios_notifyname" => "nagiosadmin")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "varnish")
  end

  it "generates the nagios_service field" do
    expect(grok).to include("nagios_service" => "Varnish Backend Connections")
  end

  it "generates the nagios_state field" do
    expect(grok).to include("nagios_state" => "CRITICAL")
  end

  it "generates the nagios_contact field" do
    expect(grok).to include("nagios_contact" => "notify-service-by-email")
  end

  it "generates the nagios_message field" do
    expect(grok).to include("nagios_message" => "Current value: 337.0, warn threshold: 10.0, crit threshold: 20.0")
  end

end


describe "NAGIOSLOGLINE - HOST NOTIFICATION" do

  let(:value)   { "[1429878690] HOST NOTIFICATION: nagiosadmin;nagioshost;DOWN;notify-host-by-email;CRITICAL - Socket timeout after 10 seconds" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "HOST NOTIFICATION")
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => 1429878690)
  end

  it "generates the nagios_notifyname field" do
    expect(grok).to include("nagios_notifyname" => "nagiosadmin")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_contact field" do
    expect(grok).to include("nagios_contact" => "notify-host-by-email")
  end

  it "generates the nagios_message field" do
    expect(grok).to include("nagios_message" => "CRITICAL - Socket timeout after 10 seconds")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: SCHEDULE_HOST_DOWNTIME" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: SCHEDULE_HOST_DOWNTIME;nagioshost;1432346400;1432360800;1;0;7200;nagiosadmin;testcomment" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "SCHEDULE_HOST_DOWNTIME")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_start_time field" do
    expect(grok).to include("nagios_start_time" => 1432346400)
  end

  it "generates the nagios_end_time field" do
    expect(grok).to include("nagios_end_time" => 1432360800)
  end

  it "generates the nagios_fixed field" do
    expect(grok).to include("nagios_fixed" => 1)
  end

  it "generates the nagios_trigger_id field" do
    expect(grok).to include("nagios_trigger_id" => 0)
  end

  it "generates the nagios_duration field" do
    expect(grok).to include("nagios_duration" => 7200)
  end

  it "generates the nagios_author field" do
    expect(grok).to include("nagios_author" => "nagiosadmin")
  end

  it "generates the nagios_comment field" do
    expect(grok).to include("nagios_comment" => "testcomment")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: SCHEDULE_SVC_DOWNTIME" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: SCHEDULE_SVC_DOWNTIME;nagioshost;nagiosservice;1432346400;1432360800;1;0;7200;nagiosadmin;testcomment" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "SCHEDULE_SVC_DOWNTIME")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_service field" do
    expect(grok).to include("nagios_service" => "nagiosservice")
  end

  it "generates the nagios_start_time field" do
    expect(grok).to include("nagios_start_time" => "1432346400")
  end

  it "generates the nagios_end_time field" do
    expect(grok).to include("nagios_end_time" => "1432360800")
  end

  it "generates the nagios_fixed field" do
    expect(grok).to include("nagios_fixed" => "1")
  end

  it "generates the nagios_trigger_id field" do
    expect(grok).to include("nagios_trigger_id" => "0")
  end

  it "generates the nagios_duration field" do
    expect(grok).to include("nagios_duration" => "7200")
  end

  it "generates the nagios_author field" do
    expect(grok).to include("nagios_author" => "nagiosadmin")
  end

  it "generates the nagios_comment field" do
    expect(grok).to include("nagios_comment" => "testcomment")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: SCHEDULE_HOST_SVC_DOWNTIME" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: SCHEDULE_HOST_SVC_DOWNTIME;nagioshost;1432346400;1432360800;1;0;7200;nagiosadmin;testcomment" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "SCHEDULE_HOST_SVC_DOWNTIME")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_start_time field" do
    expect(grok).to include("nagios_start_time" => "1432346400")
  end

  it "generates the nagios_end_time field" do
    expect(grok).to include("nagios_end_time" => "1432360800")
  end

  it "generates the nagios_fixed field" do
    expect(grok).to include("nagios_fixed" => "1")
  end

  it "generates the nagios_trigger_id field" do
    expect(grok).to include("nagios_trigger_id" => "0")
  end

  it "generates the nagios_duration field" do
    expect(grok).to include("nagios_duration" => "7200")
  end

  it "generates the nagios_author field" do
    expect(grok).to include("nagios_author" => "nagiosadmin")
  end

  it "generates the nagios_comment field" do
    expect(grok).to include("nagios_comment" => "testcomment")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: ACKNOWLEDGE_HOST_PROBLEM" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: ACKNOWLEDGE_HOST_PROBLEM;nagioshost;2;0;0;nagiosadmin;testcomment" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "ACKNOWLEDGE_HOST_PROBLEM")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_acknowlege_sticky field" do
    expect(grok).to include("nagios_acknowlege_sticky" => 2)
  end

  it "generates the nagios_acknowlege_notify field" do
    expect(grok).to include("nagios_acknowlege_notify" => 0)
  end

  it "generates the nagios_acknowlege_persistent field" do
    expect(grok).to include("nagios_acknowlege_persistent" => 0)
  end

  it "generates the nagios_author field" do
    expect(grok).to include("nagios_author" => "nagiosadmin")
  end

  it "generates the nagios_comment field" do
    expect(grok).to include("nagios_comment" => "testcomment")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: ACKNOWLEDGE_SVC_PROBLEM" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: ACKNOWLEDGE_SVC_PROBLEM;nagioshost;nagiosservice;2;0;0;nagiosadmin;testcomment" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "ACKNOWLEDGE_SVC_PROBLEM")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_service field" do
    expect(grok).to include("nagios_service" => "nagiosservice")
  end

  it "generates the nagios_acknowlege_sticky field" do
    expect(grok).to include("nagios_acknowlege_sticky" => 2)
  end

  it "generates the nagios_acknowlege_notify field" do
    expect(grok).to include("nagios_acknowlege_notify" => 0)
  end

  it "generates the nagios_acknowlege_persistent field" do
    expect(grok).to include("nagios_acknowlege_persistent" => 0)
  end

  it "generates the nagios_author field" do
    expect(grok).to include("nagios_author" => "nagiosadmin")
  end

  it "generates the nagios_comment field" do
    expect(grok).to include("nagios_comment" => "testcomment")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: SCHEDULE_HOST_CHECK & SCHEDULE_FORCED_HOST_CHECK" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: SCHEDULE_HOST_CHECK;nagioshost;1429965113" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "SCHEDULE_HOST_CHECK")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_check_time field" do
    expect(grok).to include("nagios_check_time" => "1429965113")
  end

end

describe "NAGIOSLOGLINE - EXTERNAL COMMAND: SCHEDULE_SVC_CHECK & SCHEDULE_FORCED_SVC_CHECK" do

  let(:value)   { "[1429878690] EXTERNAL COMMAND: SCHEDULE_FORCED_SVC_CHECK;nagioshost;nagiosservice;1431616619" }
  let(:grok)    { grok_match(subject, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(subject).to match(value)
  end

  it "generates the nagios_type field" do
    expect(grok).to include("nagios_type" => "EXTERNAL COMMAND")
  end

  it "generates the nagios_command field" do
    expect(grok).to include("nagios_command" => "SCHEDULE_FORCED_SVC_CHECK")
  end

  it "generates the nagios_hostname field" do
    expect(grok).to include("nagios_hostname" => "nagioshost")
  end

  it "generates the nagios_service field" do
    expect(grok).to include("nagios_service" => "nagiosservice")
  end

  it "generates the nagios_check_time field" do
    expect(grok).to include("nagios_check_time" => 1431616619)
  end

end
