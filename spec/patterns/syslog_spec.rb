# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "SYSLOGLINE" do

  it "matches a simple message with pid" do
    expect(subject).to match("May 11 15:17:02 meow.soy.se CRON[10973]: pam_unix(cron:session): session opened for user root by (uid=0)")
  end

  it "matches prog with slash" do
    expect(subject).to match("Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]")
  end

  it "matches prog from ansible" do
    expect(subject).to match("May 11 15:40:51 meow.soy.se ansible-<stdin>: Invoked with filter=* fact_path=/etc/ansible/facts.d")
  end

  it "matches prog from RFC5424 APP-NAME" do
    # https://tools.ietf.org/html/rfc5424#section-6.2.5
    # https://tools.ietf.org/html/rfc5424#section-6
    tag_from_rfc = ((33..126).map { |c| c.chr } - %w{[ ]}).join
    expect(subject).to match("May 11 15:40:51 meow.soy.se #{tag_from_rfc}: Just some data which conforms to RFC5424")
  end

  context "when having an optional progname" do

    let(:pattern) { "SYSLOGLINE" }
    let(:value)   { "<14>Jun 24 10:32:02 hostname WinFileService Event: read, Path: /.DS_Store, File/Folder: File, Size: 6.00 KB, User: user@host, IP: 123.123.123.123" }

    it "should accept the message" do
      expect(grok_match(pattern, value)).to pass
    end
  end
end
