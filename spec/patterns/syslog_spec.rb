# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "SYSLOGLINE", ['legacy', 'ecs-v1'] do

  it "matches a simple message with pid" do
    match = grok_match pattern, "May 11 15:17:02 meow.soy.se CRON[10973]: pam_unix(cron:session): session opened for user root by (uid=0)"
    if ecs_compatibility?
      expect(match).to include("process" => { "name" => "CRON", "pid" => 10973 })
    else
      expect(match).to include("pid" => "10973", "program" => "CRON")
    end
  end

  it "matches prog with slash" do
    match = grok_match pattern, "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]"
    if ecs_compatibility?
      expect(match).to include("process" => { "name" => "postfix/smtpd", "pid" => 1713 })
    else
      expect(match).to include("program" => "postfix/smtpd")
    end
  end

  it "matches prog from ansible" do
    message = "May 11 15:40:51 meow.soy.se ansible-<stdin>: Invoked with filter=* fact_path=/etc/ansible/facts.d"
    match = grok_match pattern, message
    if ecs_compatibility?
      expect(match).to include(
                           "timestamp" => "May 11 15:40:51",
                           "process" => { "name" => "ansible-<stdin>" },
                           "host" => { "hostname" => "meow.soy.se" },
                           "message" => [message, "Invoked with filter=* fact_path=/etc/ansible/facts.d"]
                       )
    else
      expect(match).to include(
                           "timestamp" => "May 11 15:40:51",
                           "logsource" => "meow.soy.se",
                           "message" => [message, "Invoked with filter=* fact_path=/etc/ansible/facts.d"]
                       )
    end
  end

  it "matches prog from RFC5424 APP-NAME" do
    # https://tools.ietf.org/html/rfc5424#section-6.2.5
    # https://tools.ietf.org/html/rfc5424#section-6
    tag_from_rfc = ((33..126).map { |c| c.chr } - %w{[ ]}).join
    match = grok_match pattern, "May 11 15:40:51 meow.soy.se #{tag_from_rfc}: Just some data which conforms to RFC5424"
    if ecs_compatibility?
      expect(match).to include("process" => { "name" => tag_from_rfc })
      expect(match).to include("host" => { "hostname" => "meow.soy.se" })
    else
      expect(match).to include("logsource" => "meow.soy.se", "program" => tag_from_rfc)
    end
  end

  it 'does not parse facility-level or msg-id' do
    message = 'May 11 10:40:48 scrooge disk-health-nurse[26783]: [ID 702911 user.error] m:SY-mon-full-500 c:H : partition health measures for /var did not suffice - still using 96% of partition space'
    match = grok_match pattern, message
    expect(match).to include("timestamp" => "May 11 10:40:48")
    expect(match).to include("message" => [message, "[ID 702911 user.error] m:SY-mon-full-500 c:H : partition health measures for /var did not suffice - still using 96% of partition space"])
    if ecs_compatibility?
      expect(match).to include("process"=>{"pid"=>26783, "name"=>"disk-health-nurse"}, "host"=>{"hostname"=>"scrooge"})
    else
      expect(match).to include("program"=>"disk-health-nurse", "pid"=>"26783", "logsource"=>"scrooge")
    end
  end

  it 'parses (non-syslog) mesages without hostname' do
    message = "Jan 11 22:33:44 su: 'su root' failed for luser on /dev/pts/8"
    match = grok_match pattern, message
    if ecs_compatibility? # in legacy mode a parse failure
      expect(match).to include("process" => { "name" => "su" })
    end
  end

  context "when having an optional progname" do

    let(:message) { "<14>Jun 24 10:32:02 win-host WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123" }

    it "should accept the message" do
      if ecs_compatibility?
        expect(grok).to include("host" => { "hostname" => "win-host" })
      else
        expect(grok).to include("logsource" => "win-host")
      end
      expect(grok['message']).to eql [message, 'WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123']
    end
  end
end

describe_pattern "SYSLOG5424LINE", ['legacy', 'ecs-v1'] do

  it "matches (ipv4 host)" do
    message = "<174>1 2016-11-14T09:49:23+01:00 10.23.16.6 named 2255 - -  info: client 10.23.56.93#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"
    match = grok_match pattern, message
    if ecs_compatibility?
      expect(match).to include("log" => { "syslog" => { "facility" => { "code" => 174 }}})
      expect(match).to include("host" => { "hostname" => "10.23.16.6"})
      expect(match).to include("process" => { "name" => "named", "pid" => 2255 })
      expect(match).to include("system" => { "syslog" => { "version" => "1" }})
      expect(match).to include("timestamp" => "2016-11-14T09:49:23+01:00")
      expect(match).to include("message" => [message, "info: client 10.23.56.93#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"])
    else
      expect(match).to include({
                                   "syslog5424_pri" => "174",
                                   "syslog5424_host" => "10.23.16.6",
                                   "syslog5424_app" => "named",
                                   "syslog5424_ver" => "1",
                                   "syslog5424_proc" => "2255",
                                   "syslog5424_ts" => "2016-11-14T09:49:23+01:00",
                                   "syslog5424_msg" => "info: client 10.23.56.93#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"
                               })
      expect(match).to include("message" => message)
    end
  end

  it "matches ipv6 host" do
    message = "<174>1 1995-04-12T23:20:50.52Z 2000:6a0:b:315:10:23:4:13 named 2255 - -  info: client 10.23.56.9#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"
    match = grok_match pattern, message
    if ecs_compatibility?
      expect(match).to include("host" => { "hostname" => "2000:6a0:b:315:10:23:4:13" })
      expect(match).to include("timestamp" => "1995-04-12T23:20:50.52Z")
      expect(match).to include("message" => [message, "info: client 10.23.56.9#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"])
    else
      expect(match).to include("syslog5424_host" => "2000:6a0:b:315:10:23:4:13")
      expect(match).to include("syslog5424_ts" => "1995-04-12T23:20:50.52Z")
    end
  end

  it "matches host name" do
    message = "<174>1 2016-12-31T23:59:60-04:00 resolver.se prg00000[1234] - -  info: client 10.23.53.22#63252: query: googlehosted.l.googleusercontent.com IN A + (10.23.16.6)"
    match = grok_match pattern, message
    if ecs_compatibility?
      expect(match).to include("host" => { "hostname" => "resolver.se" })
      expect(match).to include("message" => [message, "info: client 10.23.53.22#63252: query: googlehosted.l.googleusercontent.com IN A + (10.23.16.6)"])
      expect(match).to include("timestamp" => "2016-12-31T23:59:60-04:00")
      expect(match['system']['syslog'].keys).to_not include("message_id")
    else
      expect(match).to include("syslog5424_host" => "resolver.se")
      expect(match).to include("syslog5424_ts" => "2016-12-31T23:59:60-04:00")
      expect(match.keys).to_not include("syslog5424_msgid")
    end
  end

  it "matches nil host-name" do
    message = "<174>1 2003-08-24T05:14:15+00:00 - - - - - IN=enx503f560021dc OUT= MAC=01:00:5e:00:00:01:88:f8:c7:8b:1a:b4:04:00 SRC=192.168.81.1 DST=224.0.0.1 LEN=32 TOS=0x00 PREC=0xC0 TTL=1 ID=0 PROTO=2"
    match = grok_match pattern, message
    if ecs_compatibility?
      expect(match).to include("timestamp" => "2003-08-24T05:14:15+00:00")
      expect(match.keys).to_not include("host")
    else
      expect(match.keys).to_not include("syslog5424_host")
    end
  end

  it 'matches milli-second precision timestamp' do
    match = grok_match pattern, "<34>1 2003-08-24T05:14:15.123-07:00 the.borg.com su - ID47 - BOM'su root' failed for borg on /dev/pts/7"
    if ecs_compatibility?
      expect(match).to include("timestamp" => "2003-08-24T05:14:15.123-07:00")
      expect(match).to include("process" => { "name" => "su" })
    else
      expect(match).to include("syslog5424_ts" => "2003-08-24T05:14:15.123-07:00")
    end
  end

  it 'matches milli-second precision timestamp (Z) and msgid' do
    match = grok_match pattern, "<34>1 2030-10-11T22:14:15.003Z the.borg.com su - m:WR-ID47 - BOM'su root' failed for borg on /dev/pts/7"
    if ecs_compatibility?
      expect(match).to include("timestamp" => "2030-10-11T22:14:15.003Z")
      expect(match).to include("system" => { "syslog" =>  hash_including("msgid" => 'm:WR-ID47') })
    else
      expect(match).to include("syslog5424_ts" => "2030-10-11T22:14:15.003Z")
      expect(match).to include("syslog5424_msgid" => "m:WR-ID47")
    end
  end

  it 'matches micro-second precision timestamp and structured-data' do
    message = "<34>1 2012-12-19T01:45:54.001234Z rufus - - - [meta sequenceId=10] BOMStack unit 3 Power supply 2 is down"
    match = grok_match pattern, message
    p match
    if ecs_compatibility?
      expect(match).to include("timestamp" => "2012-12-19T01:45:54.001234Z")
      expect(match).to include("system" => { "syslog" =>  hash_including("structured_data" => '[meta sequenceId=10]') })
      expect(match).to include("message" => [message, "BOMStack unit 3 Power supply 2 is down"])

      expect(match.keys).to_not include("process")
    else
      expect(match).to include("syslog5424_ts" => "2012-12-19T01:45:54.001234Z")
      expect(match).to include("syslog5424_sd" => "[meta sequenceId=10]")
      expect(match).to include("syslog5424_msg" => "BOMStack unit 3 Power supply 2 is down")
    end
  end

  it 'matches more structured-data' do
    sd = '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]'
    message = "<34>1 2012-12-19T01:45:54.001234+11:30 rufus - - - #{sd} [down]"
    match = grok_match pattern, message
    p match
    if ecs_compatibility?
      expect(match).to include("system" => { "syslog" =>  hash_including("structured_data" => sd) })
      expect(match).to include("message" => [message, "[down]"])
    else
      expect(match).to include("syslog5424_sd" => sd)
      expect(match).to include("syslog5424_msg" => "[down]")
    end
  end

end

describe_pattern 'SYSLOGPAMSESSION', ['legacy', 'ecs-v1'] do

  it "matches" do
    message = 'Jul 14 13:36:03 precision pkexec: pam_unix(polkit-1:session): session opened for user root by (uid=1001)'
    match = grok_match pattern, message
    expect(match).to include("timestamp" => "Jul 14 13:36:03")
    if ecs_compatibility?
      expect(match).to include(
                           "host" => { "hostname" => "precision" },
                           "process" => { "name" => "pkexec" },
                           "user" => { "name" => "root" },
                           "system" => { "auth" => {
                               "pam" => { "module" => "pam_unix", "origin" => "polkit-1:session", "session_state" => "opened" }}
                           }
                       )
    else
      expect(match).to include({
                                   "logsource"=>"precision",
                                   "program"=>"pkexec",
                                   "username"=>"root",
                                   "pam_module"=>"pam_unix",
                                   "pam_caller"=>"polkit-1:session",
                                   "pam_session_state"=>"opened",
                                   "pam_by"=>"(uid=1001)",
                               })
    end
    expect(match).to include("message" => [message, "pam_unix(polkit-1:session): session opened for user root by (uid=1001)"])
  end

  it "matches a message with pid" do
    message = 'Jul 14 12:17:01.234 precision.computer CRON[869567]: pam_unix(cron:session): session closed for user root'
    match = grok_match pattern, message
    expect(match).to include("timestamp" => "Jul 14 12:17:01.234")
    if ecs_compatibility?
      expect(match).to include(
                           "host" => { "hostname" => "precision.computer" },
                           "process" => { "name" => "CRON", "pid" => 869567 },
                           "user" => { "name" => "root" },
                           "system" => { "auth" => {
                               "pam" => { "module" => "pam_unix", "origin" => "cron:session", "session_state" => "closed" }}
                           }
                       )
    else
      expect(match).to include({
                                   "logsource" => "precision.computer",
                                   "program" => "CRON",
                                   "username" => "root",
                                   "pid" => "869567",
                                   "pam_module" => "pam_unix",
                                   "pam_caller" => "cron:session",
                                   "pam_session_state" => "closed"
                               })
    end
    expect(match).to include("message" => [message, "pam_unix(cron:session): session closed for user root"])
  end

end

describe_pattern 'CRONLOG', ['legacy', 'ecs-v1'] do

  it "matches" do
    message = 'Jul 17 12:17:01 precision CRON[869568]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)'
    match = grok_match pattern, message
    expect(match).to include("timestamp" => "Jul 17 12:17:01")
    if ecs_compatibility?
      expect(match).to include(
                           "host" => { "hostname" => "precision" },
                           "process" => { "name" => "CRON", "pid" => 869568 },
                           "user" => { "name" => "root" },
                           "system" => { "cron" => { "action" => "CMD" } }
                       )
    else
      expect(match).to include(
                           "logsource"=>"precision",
                           "program"=>"CRON",
                           "pid"=>"869568",
                           "user"=>"root",
                           "action"=>"CMD"
                       )
    end
    expect(match).to include("message"=>[message, "   cd / && run-parts --report /etc/cron.hourly"])
  end

end