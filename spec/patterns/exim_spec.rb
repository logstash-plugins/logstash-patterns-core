# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern 'EXIM', ['legacy', 'ecs-v1'] do

  context 'message arrival (old)' do

    let(:message) do
      "1995-10-31 08:57:53 0tACW1-0005MB-00 <= kryten@dwarf.fict.example H=mailer.fict.example [192.168.123.123] " +
          "U=exim P=smtp S=5678 id=f828ca60127d8646a0fa75cbf8db9ba3@dwarf.fict.example"
    end

    it "matches" do
      expect(grok).to include("timestamp" => "1995-10-31 08:57:53")

      if ecs_compatibility?
        expect(grok).to include("exim"=>{"log"=>{
            "flags"=>"<=",
            "sender"=>{"email"=>"kryten@dwarf.fict.example"},
            "message"=>{"id"=>"0tACW1-0005MB-00", "size"=>5678},
            "header_id"=>"f828ca60127d8646a0fa75cbf8db9ba3@dwarf.fict.example"
        }})
        expect(grok).to include("source"=>{"address"=>"mailer.fict.example", "ip"=>"192.168.123.123"})
        expect(grok).to include("network"=>{"protocol"=>"smtp"})
      else
        expect(grok).to include("exim_year" => "1995", "exim_month" => "10", "exim_day" => "31", "@version" => "1", "exim_time" => "08:57:53")
        expect(grok.keys).to_not include("pid")
        expect(grok).to include("exim_sender_email" => "kryten@dwarf.fict.example")
        expect(grok).to include("exim_flags" => "<=")
        expect(grok).to include("exim_msg_size" => "5678")
        expect(grok).to include("exim_msgid" => "0tACW1-0005MB-00")
        expect(grok).to include("remote_hostname" => "mailer.fict.example", "remote_host" => "192.168.123.123")
        expect(grok).to include("protocol" => "smtp")
        expect(grok).to include("exim_header_id" => "f828ca60127d8646a0fa75cbf8db9ba3@dwarf.fict.example")
      end

      expect(grok).to include("message" => message)
    end

  end

  context 'message arrival (new)' do
    let(:message) do
      '2010-09-13 05:00:13 [1487] 1Ov4tU-0000Nz-Rm <= mailling.list@domain.com ' +
          'H=mailhost.domain.com [208.42.54.2]:51792 I=[67.215.162.175]:25 P=esmtps X=TLSv1:AES256-SHA:256 CV=no S=21778 ' +
          'id=384a86a39e83be0d9b3a94d1feb3119f@domain.com T="Daily List: Chameleon" for user@example.com'
    end

    it "matches" do
      expect(grok).to include("timestamp" => "2010-09-13 05:00:13") # new in legacy mode

      if ecs_compatibility?
        expect(grok).to include("process"=>{"pid"=>1487})
        expect(grok).to include("exim"=>{"log"=>hash_including(
            "message"=>{"id"=>"1Ov4tU-0000Nz-Rm", "size"=>21778, "subject"=>"Daily List: Chameleon"},
            "flags"=>"<=",
            "header_id"=>"384a86a39e83be0d9b3a94d1feb3119f@domain.com",
            "sender"=>{"email"=>"mailling.list@domain.com"},
            "recipient"=>{"email"=>"user@example.com"},
        )})
        expect(grok).to include("source"=>{"address"=>"mailhost.domain.com", "ip"=>"208.42.54.2", "port"=>51792})
        expect(grok).to include("destination"=>{"ip"=>"67.215.162.175", "port"=>25})
      else

        expect(grok).to include("exim_year" => "2010", "exim_month" => "09", "exim_day" => "13", "exim_time" => "05:00:13")
        expect(grok).to include("pid" => "1487") # new
        expect(grok).to include("exim_sender_email" => "mailling.list@domain.com") # new
        expect(grok).to include("remote_hostname" => "mailhost.domain.com", "remote_host" => "208.42.54.2", "remote_port" => "51792") # (remote_port) new
        expect(grok).to include("exim_interface" => "67.215.162.175", "exim_interface_port" => "25")
        expect(grok).to include("protocol" => "esmtps")
        expect(grok).to include("exim_msg_size" => "21778")
        expect(grok).to include("exim_header_id" => "384a86a39e83be0d9b3a94d1feb3119f@domain.com")
        expect(grok).to include("exim_subject" => '"Daily List: Chameleon"')
        expect(grok).to include("exim_recipient_email" => "user@example.com") # new
      end

      expect(grok).to include("message" => message)
    end

  end

  context 'message arrival (simple)' do

    let(:message) do
      '2020-02-11 17:09:46 1j1Z2g-00Faoy-Uh <= example@strawberry.active-ns.com U=example P=local ' +
          'T="[Examples Galore] Please moderate: \"Hello world!\"" for admin@example.net'
    end

    it "matches" do
      expect(grok).to include("timestamp"=>"2020-02-11 17:09:46")
      if ecs_compatibility?
        expect(grok).to include("exim"=>{"log"=>{
            "flags"=>"<=",
            "message"=>{"id"=>"1j1Z2g-00Faoy-Uh", "subject"=>'[Examples Galore] Please moderate: \\"Hello world!\\"'},
            "sender"=>{"email"=>"example@strawberry.active-ns.com"},
            "recipient"=>{"email"=>"admin@example.net"}
        }})
        expect(grok).to include("network"=>{"protocol"=>"local"})
      else
        expect(grok).to include(
                            "exim_msgid"=>"1j1Z2g-00Faoy-Uh",
                            "exim_sender_email"=>"example@strawberry.active-ns.com",
                            "exim_flags"=>"<=",
                            "protocol"=>"local",
                            "exim_subject"=>"\"[Examples Galore] Please moderate: \\\"Hello world!\\\"\""
                        )
      end
    end

  end

  context 'message arrival with quoted hostname' do

    let(:message) do
      '2013-03-20 12:44:02 1UIIN7-0004t9-8R <= root@example.com ' +
          'H=localhost (hostname.example.com) [127.0.0.1] ' +
          'P=esmtps X=TLSv1:DHE-RSA-AES256-SHA:256 S=811 id=201303201244.r2KCi11V018784@hostname.example.com'
    end

    it "matches" do
      expect(grok).to include("timestamp"=>"2013-03-20 12:44:02")

      if ecs_compatibility?
        expect(grok).to include("exim"=>{"log"=>hash_including(
            "sender"=>{ "email"=>"root@example.com" },
            "message"=>{ "id"=>"1UIIN7-0004t9-8R", "size"=>811 },
            "header_id"=>"201303201244.r2KCi11V018784@hostname.example.com",
            "remote_address"=>"hostname.example.com")})
        expect(grok).to include("source"=>{"address"=>"localhost", "ip"=>"127.0.0.1"})
        expect(grok).to include("network"=>{"protocol"=>"esmtps"})
      else
        expect(grok).to include(
                            "exim_msgid"=>"1UIIN7-0004t9-8R",
                            "exim_sender_email"=>"root@example.com",
                            "exim_flags"=>"<=",
                            "protocol"=>"esmtps",
                            "exim_header_id"=>"201303201244.r2KCi11V018784@hostname.example.com"
                            )
        expect(grok).to include(
                            "remote_host"=>"127.0.0.1",
                            "remote_heloname"=>"hostname.example.com",
                            "remote_hostname"=>"localhost"
                        )
      end
    end

  end


  context 'message arrival with quoted hostname and port' do

    let(:message) do
      '2014-08-10 11:18:35 [28107] 1gsu1C-003dCu-Hb <= aaron@domain.com ' +
          'H=localhost (10.5.40.204) [127.0.0.1]:39753 I=[127.0.0.1]:25 ' +
          'P=esmtpa A=dovecot_plain:aaron@domain.com S=4315 M8S=0 id=d2b648f00f1a1b0813c483d552778dc6@domain.com ' +
          "T=\"what's up?!? ;-)\" from <aaron@domain.com> for aaron+forward@domain.com"
    end

    it "matches" do
      if ecs_compatibility?
        expect(grok).to include("exim"=>{"log"=>hash_including(
            "message"=>hash_including("id"=>"1gsu1C-003dCu-Hb", "subject"=>"what's up?!? ;-)"),
        )})
        expect(grok).to include("destination"=>{"ip"=>"127.0.0.1", "port"=>25})
        expect(grok).to include("exim"=>{"log"=>hash_including(
            "sender"=>{"email"=>"aaron@domain.com", 'original'=>'aaron@domain.com'}
        )})
        expect(grok).to include("exim"=>{"log"=>hash_including("recipient"=>{"email"=>"aaron+forward@domain.com"})})
        expect(grok).to include("source"=>{"address"=>"localhost", "ip"=>"127.0.0.1", "port"=>39753})
        expect(grok).to include("exim"=>{"log" => hash_including("remote_address"=>'10.5.40.204')})
      else
        expect(grok).to include(
                            "exim_msgid"=>"1gsu1C-003dCu-Hb",
                            "exim_sender_email"=>"aaron@domain.com",
                            "exim_flags"=>"<=",
                            "protocol"=>"esmtpa"
                        )
        expect(grok).to include(
                            "remote_host"=>"127.0.0.1", "remote_port"=>"39753",
                            "remote_heloname"=>"10.5.40.204",
                            "remote_hostname"=>"localhost"
                        )
      end
    end

  end

  context 'delivery failed' do

    let(:message) do
      '2020-02-11 17:09:47 1j1Z2g-00Faoy-Uh ** admin@example.net R=virtual_aliases: No such person at this address.'
    end

    it "does not parse" do # matching not implemented
      expect(grok['tags']).to include("_grokparsefailure")
    end

  end

end
