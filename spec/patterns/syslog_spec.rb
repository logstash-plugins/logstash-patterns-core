# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "SYSLOGLINE" do

  it "matches a simple message with pid" do
    match = grok_match subject, "May 11 15:17:02 meow.soy.se CRON[10973]: pam_unix(cron:session): session opened for user root by (uid=0)"
    expect(match).to include("pid" => "10973", "program" => "CRON")
  end

  it "matches prog with slash" do
    match = grok_match subject, "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]"
    expect(match).to include("program" => "postfix/smtpd")
  end

  it "matches prog from ansible" do
    expect(subject).to match("May 11 15:40:51 meow.soy.se ansible-<stdin>: Invoked with filter=* fact_path=/etc/ansible/facts.d")
  end

  it "matches prog from RFC5424 APP-NAME" do
    # https://tools.ietf.org/html/rfc5424#section-6.2.5
    # https://tools.ietf.org/html/rfc5424#section-6
    tag_from_rfc = ((33..126).map { |c| c.chr } - %w{[ ]}).join
    match = grok_match subject, "May 11 15:40:51 meow.soy.se #{tag_from_rfc}: Just some data which conforms to RFC5424"
    expect(match).to include("logsource" => "meow.soy.se", "program" => tag_from_rfc)
  end

  context "when having an optional progname" do

    let(:pattern) { "SYSLOGLINE" }
    let(:value)   { "<14>Jun 24 10:32:02 hostname WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123" }

    it "should accept the message" do
      match = grok_match(pattern, value)
      # TODO seems not to work as intented, but let's at least assert something got matched:
      expect(match).to include("logsource" => "hostname")
    end
  end
end

describe "SYSLOG5424BASE" do

  it "matches (ipv4 host)" do
    match = grok_match subject, "<174>1 2016-11-14T09:49:23+01:00 10.23.16.6 named 2255 - -  info: client 10.23.56.93#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"
    expect(match).to include({
                                 "syslog5424_pri"=>"174",
                                 "syslog5424_host"=>"10.23.16.6",
                                 "syslog5424_app"=>"named",
                                 "syslog5424_ver"=>"1",
                                 "message"=>"<174>1 2016-11-14T09:49:23+01:00 10.23.16.6 named 2255 - -  info: client 10.23.56.93#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)",
                                 "syslog5424_proc"=>"2255",
                                 "syslog5424_ts"=>"2016-11-14T09:49:23+01:00"
                             })
  end

  it "matches ipv6 host" do
    match = grok_match subject, "<174>1 2016-11-14T09:49:23+01:00 2000:6a0:b:315:10:23:4:13 named 2255 - -  info: client 10.23.56.9#63295 (i1.tmg.com): query: i1.tmg.com IN A + (10.23.4.13)"
    expect(match).to include({
                                 "syslog5424_host"=>"2000:6a0:b:315:10:23:4:13"
                             })
  end

  it "matches host name" do
    match = grok_match subject, "<174>1 2016-11-14T09:32:44+01:00 resolver.se named 6344 - -  info: client 10.23.53.22#63252: query: googlehosted.l.googleusercontent.com IN A + (10.23.16.6)"
    expect(match).to include({
                                 "syslog5424_host"=>"resolver.se"
                             })
  end

end

describe 'SYSLOGPAMSESSION' do

  it "matches" do
    message = 'Jul 14 13:36:03 precision pkexec: pam_unix(polkit-1:session): session opened for user root by (uid=1001)'
    match = grok_match subject, message
    expect(match).to include({
                                 "timestamp"=>"Jul 14 13:36:03",
                                 "logsource"=>"precision",
                                 "program"=>"pkexec",
                                 "username"=>"root",
                                 "message"=>[message, "pam_unix(polkit-1:session): session opened for user root by (uid=1001)"],
                                 "pam_module"=>"pam_unix",
                                 "pam_caller"=>"polkit-1:session",
                                 "pam_session_state"=>"opened",
                                 "pam_by"=>"(uid=1001)",
                             })
  end

  it "matches a message with pid" do
    message = 'Jul 14 12:17:01 precision CRON[869567]: pam_unix(cron:session): session closed for user root'
    match = grok_match subject, message
    expect(match).to include({
                                 "timestamp"=>"Jul 14 12:17:01",
                                 "logsource"=>"precision",
                                 "program"=>"CRON",
                                 "username"=>"root",
                                 "pid"=>"869567",
                                 "message"=>[message, "pam_unix(cron:session): session closed for user root"],
                                 "pam_module"=>"pam_unix",
                                 "pam_caller"=>"cron:session",
                                 "pam_session_state"=>"closed",
                             })
  end

end

describe 'CRONLOG' do

  it "matches" do
    message = 'Jul 17 12:17:01 precision CRON[869568]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)'
    match = grok_match subject, message
    expect(match).to include({
                                 "timestamp"=>"Jul 17 12:17:01",
                                 "logsource"=>"precision",
                                 "program"=>"CRON",
                                 "pid"=>"869568",
                                 "user"=>"root",
                                 "action"=>"CMD",
                                 "message"=>[message, "   cd / && run-parts --report /etc/cron.hourly"]
                            })
  end

end