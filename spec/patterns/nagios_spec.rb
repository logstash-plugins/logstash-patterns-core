# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "NAGIOSLOGLINE - CURRENT HOST STATE", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1427925600] CURRENT HOST STATE: nagioshost;UP;HARD;1;PING OK - Packet loss = 0%, RTA = 2.24 ms" }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(pattern).to match(message)
  end

  it "generates the nagios_epoch field" do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1427925600")
    else
      expect(grok).to include("nagios_epoch" => "1427925600")
    end
  end

  it "generates the nagios_message field" do
    if ecs_compatibility?
      expect(grok).to include("message" => [message, "PING OK - Packet loss = 0%, RTA = 2.24 ms"])
    else
      expect(grok).to include("nagios_message" => "PING OK - Packet loss = 0%, RTA = 2.24 ms")
    end
  end

  it "generates the nagios_hostname field" do
    if ecs_compatibility?
      expect(grok).to include("host" => { "hostname" => "nagioshost" })
    else
      expect(grok).to include("nagios_hostname" => "nagioshost")
    end
  end

  it "generates the nagios_state field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("status" => "UP")))
    else
      expect(grok).to include("nagios_state" => "UP")
    end
  end

  it "generates the nagios_statetype field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("state_type" => "HARD")))
    else
      expect(grok).to include("nagios_statetype" => "HARD")
    end
  end

end

describe_pattern "NAGIOSLOGLINE - CURRENT SERVICE STATE", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1427925600] CURRENT SERVICE STATE: nagioshost;SSH;OK;HARD;1;nagiosmessage" }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(pattern).to match(message)
  end

  it "generates the nagios_type field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("type" => "CURRENT SERVICE STATE")))
    else
      expect(grok).to include("nagios_type" => "CURRENT SERVICE STATE")
    end
  end

  it "generates the nagios_epoch field" do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1427925600")
    else
      expect(grok).to include("nagios_epoch" => "1427925600")
    end
  end

  it "generates the nagios_message field" do
    if ecs_compatibility?
      expect(grok).to include("message" => [message, "nagiosmessage"])
    else
      expect(grok).to include("nagios_message" => "nagiosmessage")
    end
  end

  it "generates the nagios_hostname field" do
    if ecs_compatibility?
      expect(grok).to include("host" => { "hostname" => "nagioshost" })
    else
      expect(grok).to include("nagios_hostname" => "nagioshost")
    end
  end

  it "generates the nagios_service field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("service" => "SSH")))
    else
      expect(grok).to include("nagios_service" => "SSH")
    end
  end

  it "generates the nagios_state field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("status" => "OK")))
    else
      expect(grok).to include("nagios_state" => "OK")
    end
  end

  it "generates the nagios_statetype field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("state_type" => "HARD")))
    else
      expect(grok).to include("nagios_statetype" => "HARD")
    end
  end

  it "generates the nagios_statecode field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("attempt" => 1)))
    else
      # NOTE: (legacy) nagios_statecode corresponds to current_attempt (according to Nagios' source)
      expect(grok).to include("nagios_statecode" => "1")
    end
  end

  context 'real-world example' do

    let(:message) do
      '[1427956600] CURRENT SERVICE STATE: prod-virtual-ESz06;check_vmfs_prod-PvDC2;CRITICAL;HARD;3;CRITICAL - /vmfs/volumes/prod-vsRoot - total: 8191.75 Gb - used: 7859.84 Gb (95%)- free: 331.90 Gb (5%)'
    end

    it 'matches' do
      if ecs_compatibility?
        expect(grok).to include(
          "host" => { "hostname" => "prod-virtual-ESz06" },
          "nagios" => { "log" => {
              "type" => "CURRENT SERVICE STATE",
              "status" => "CRITICAL",
              "state_type" => "HARD",
              "attempt" => 3,
              "service" => "check_vmfs_prod-PvDC2"
          }},
          "message" => [message, "CRITICAL - /vmfs/volumes/prod-vsRoot - total: 8191.75 Gb - used: 7859.84 Gb (95%)- free: 331.90 Gb (5%)"]
        )
      else
        expect(grok).to include(
          "nagios_type"=>"CURRENT SERVICE STATE",
          "nagios_state"=>"CRITICAL",
          "nagios_statetype"=>"HARD",
          "nagios_hostname"=>"prod-virtual-ESz06",
          "nagios_statecode"=>"3", # NOTE: "incorrect" - corresponds to current_attempt (according to Nagios' source)
          "nagios_message"=>"CRITICAL - /vmfs/volumes/prod-vsRoot - total: 8191.75 Gb - used: 7859.84 Gb (95%)- free: 331.90 Gb (5%)"
        )
      end
    end

  end
end

describe_pattern "NAGIOSLOGLINE - TIMEPERIOD TRANSITION", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1427925600] TIMEPERIOD TRANSITION: 24X7;-1;1" }

  it "matches the message" do
    expect(pattern).to match(message)
  end

  it "generates the nagios_type field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("type" => 'TIMEPERIOD TRANSITION')))
    else
      expect(grok).to include("nagios_type" => "TIMEPERIOD TRANSITION")
    end
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => "1427925600") unless ecs_compatibility?
  end

  it "generates the nagios_service field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("service" => '24X7')))
    else
      expect(grok).to include("nagios_service" => "24X7")
    end
  end

  it "generates the period from/to fields" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("period_from" => -1, "period_to" => 1)))
    else
      expect(grok).to include("nagios_unknown1" => "-1", "nagios_unknown2" => "1")
    end
  end

  # Regression test for but fixed in Nagios patterns #30
  it "doesn't end in a semi-colon" do
    message = grok['message']
    message = message.last if message.is_a?(Array)
    expect(message).to_not end_with(";")
  end

end

describe_pattern "NAGIOSLOGLINE - SERVICE ALERT", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1427925689] SERVICE ALERT: varnish;Varnish Backend Connections;CRITICAL;SOFT;1;Current value: 154.0, warn threshold: 10.0, crit threshold: 20.0" }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(pattern).to match(message)
  end

  it "generates the nagios_type field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("type" => 'SERVICE ALERT')))
    else
      expect(grok).to include("nagios_type" => "SERVICE ALERT")
    end
  end

  it "generates the nagios_epoch field" do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1427925689")
    else
      expect(grok).to include("nagios_epoch" => "1427925689")
    end
  end

  it "generates the nagios_hostname field" do
    if ecs_compatibility?
      expect(grok).to include("host" => { "hostname" => "varnish" })
    else
      expect(grok).to include("nagios_hostname" => "varnish")
    end
  end

  it "generates the nagios_service field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("service" => 'Varnish Backend Connections')))
    else
      expect(grok).to include("nagios_service" => "Varnish Backend Connections")
    end
  end

  it "generates the nagios_state field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("status" => "CRITICAL")))
    else
      expect(grok).to include("nagios_state" => "CRITICAL")
    end
  end

  it "generates the nagios_statelevel field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("state_type" => "SOFT")))
    else
      expect(grok).to include("nagios_statelevel" => "SOFT")
    end
  end

  it "generates the nagios_attempt field" do
    if ecs_compatibility?
      p grok
      expect(grok).to include("nagios" => hash_including("log" => hash_including("attempt" => 1)))
    else
      p grok
      expect(grok).to include("nagios_attempt" => "1")
    end
  end

  it "generates the nagios_message field" do
    if ecs_compatibility?
      expect(grok['message'].last).to eql "Current value: 154.0, warn threshold: 10.0, crit threshold: 20.0"
    else
      expect(grok).to include("nagios_message" => "Current value: 154.0, warn threshold: 10.0, crit threshold: 20.0")
    end
  end

end

describe_pattern "NAGIOSLOGLINE - SERVICE NOTIFICATION", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1427950229] SERVICE NOTIFICATION: nagiosadmin;varnish;Varnish Backend Connections;CRITICAL;notify-service-by-email;Current value: 337.0, warn threshold: 10.0, crit threshold: 20.0" }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "matches a simple message" do
    expect(pattern).to match(message)
  end

  it "generates the nagios_type field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("type" => 'SERVICE NOTIFICATION')))
    else
      expect(grok).to include("nagios_type" => "SERVICE NOTIFICATION")
    end
  end

  it "generates the nagios_epoch field" do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1427950229")
    else
      expect(grok).to include("nagios_epoch" => "1427950229")
    end
  end

  it "generates the nagios_notifyname field" do
    if ecs_compatibility?
      expect(grok).to include("user" => { "name" => "nagiosadmin" }) # Nagios contact's contact_name
    else
      expect(grok).to include("nagios_notifyname" => "nagiosadmin")
    end
  end

  it "generates the nagios_hostname field" do
    if ecs_compatibility?
      expect(grok).to include("host" => { "hostname" => "varnish" })
    else
      expect(grok).to include("nagios_hostname" => "varnish")
    end
  end

  it "generates the nagios_service field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("service" => 'Varnish Backend Connections')))
    else
      expect(grok).to include("nagios_service" => "Varnish Backend Connections")
    end
  end

  it "generates the nagios_state field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("status" => "CRITICAL")))
    else
      expect(grok).to include("nagios_state" => "CRITICAL")
    end
  end

  it "generates the nagios_contact field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("notification_command" => "notify-service-by-email")))
    else
      expect(grok).to include("nagios_contact" => "notify-service-by-email")
    end
  end

  it "generates the nagios_message field" do
    if ecs_compatibility?
      expect(grok['message'].last).to eql "Current value: 337.0, warn threshold: 10.0, crit threshold: 20.0"
    else
      expect(grok).to include("nagios_message" => "Current value: 337.0, warn threshold: 10.0, crit threshold: 20.0")
    end
  end

end


describe_pattern "NAGIOSLOGLINE - HOST NOTIFICATION", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1429878690] HOST NOTIFICATION: nagiosadmin;127.0.0.1;DOWN;host-notify-by-email;CRITICAL - Socket timeout after 10 seconds" }

  it "matches a simple message" do
    expect(pattern).to match(message)
  end

  it "generates the nagios_type field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("type" => "HOST NOTIFICATION")))
    else
      expect(grok).to include("nagios_type" => "HOST NOTIFICATION")
    end
  end

  it "generates the nagios_epoch field" do
    expect(grok).to include("nagios_epoch" => "1429878690") unless ecs_compatibility?
  end

  it "generates the nagios_notifyname field" do
    if ecs_compatibility?
      expect(grok).to include("user" => { "name" => "nagiosadmin" }) # Nagios contact's contact_name
    else
      expect(grok).to include("nagios_notifyname" => "nagiosadmin")
    end
  end

  it "generates the nagios_hostname field" do
    if ecs_compatibility?
      expect(grok).to include("host" => { "hostname" => "127.0.0.1" })
    else
      expect(grok).to include("nagios_hostname" => "127.0.0.1")
    end
  end

  it "generates the nagios_contact field" do
    if ecs_compatibility?
      expect(grok).to include("nagios" => hash_including("log" => hash_including("notification_command" => "host-notify-by-email")))
    else
      expect(grok).to include("nagios_contact" => "host-notify-by-email")
    end
  end

  it "generates the nagios_message field" do
    if ecs_compatibility?
      expect(grok['message'].last).to eql "CRITICAL - Socket timeout after 10 seconds"
    else
      expect(grok).to include("nagios_message" => "CRITICAL - Socket timeout after 10 seconds")
    end
  end

end

describe_pattern "NAGIOSLOGLINE - SCHEDULE_HOST_DOWNTIME", [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[1334609999] EXTERNAL COMMAND: SCHEDULE_HOST_DOWNTIME;sputnik;1334665800;1334553600;1;0;120;nagiosadmin;test;" }

  it "matches" do
    if ecs_compatibility?
      expect(grok).to include(
                          "host" => { "hostname" => "sputnik" },
                          "nagios" => { "log" => {
                              "type" => "EXTERNAL COMMAND",
                              "command" => "SCHEDULE_HOST_DOWNTIME",
                              "start_time" => "1334665800",
                              "end_time" => "1334553600",
                              "fixed" => '1',
                              "trigger_id" => '0',
                              "duration" => 120,

                          }},
                          "user" => { "name" => 'nagiosadmin' },
                          "message" => message
                      )
    else
      expect(grok).to include(
                          "nagios_epoch"=>"1334609999",
                          "nagios_type"=>"EXTERNAL COMMAND",
                          "nagios_command"=>"SCHEDULE_HOST_DOWNTIME",
                          "nagios_hostname"=>"sputnik",
                          "nagios_duration"=>"120",
                          "nagios_fixed"=>"1",
                          "nagios_trigger_id"=>"0",
                          "nagios_start_time"=>"1334665800",
                          "nagios_end_time"=>"1334553600",
                          "author"=>"nagiosadmin"
      )
    end
  end
end
