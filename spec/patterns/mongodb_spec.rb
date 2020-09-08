# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "MONGO3_LOG", ['legacy', 'ecs-v1'] do

  context "parsing an standard/basic message" do

    let(:message) { "2014-11-03T18:28:32.450-0500 I NETWORK [initandlisten] waiting for connections on port 27017" }

    it { should include("timestamp" => "2014-11-03T18:28:32.450-0500") }

    it do
      if ecs_compatibility?
        should include("log" => { 'level' => "I" })
      else
        should include("severity" => "I")
      end
    end

    it do
      if ecs_compatibility?
        should include("mongodb" => hash_including("component" => "NETWORK"))
      else
        should include("component" => "NETWORK")
      end
    end

    it do
      if ecs_compatibility?
        should include("mongodb" => hash_including("context" => "initandlisten"))
      else
        should include("context" => "initandlisten")
      end
    end

    it "generates a message field" do
      expect(subject["message"]).to eql [ message, "waiting for connections on port 27017" ]
    end
  end

  context "parsing a message with a missing component" do

    let(:message) { "2015-02-24T18:17:47.148+0000 F -        [conn11] Got signal: 11 (Segmentation fault)." }

    it 'matches' do
      should include("timestamp" => "2015-02-24T18:17:47.148+0000")

      if ecs_compatibility?
        expect( grok_result['mongodb'].keys ).to_not include("component")
      else
        should include("component" => "-")
      end

      if ecs_compatibility?
        should include("log" => { 'level' => "F" })
      else
        should include("severity" => "F")
      end

      if ecs_compatibility?
        should include("mongodb" => hash_including("context" => "conn11"))
      else
        should include("context" => "conn11")
      end
    end

    it "generates a message field" do
      expect(subject["message"]).to eql [ message, "Got signal: 11 (Segmentation fault)." ]
    end
  end

  context "parsing a message with a multiwords context" do

    let(:message) { "2015-04-23T06:57:28.256+0200 I JOURNAL  [journal writer] Journal writer thread started" }

    it 'matches' do
      should include("timestamp" => "2015-04-23T06:57:28.256+0200")

      if ecs_compatibility?
        should include("log" => { 'level' => "I" })
      else
        should include("severity" => "I")
      end

      if ecs_compatibility?
        should include("mongodb" => hash_including("component" => "JOURNAL"))
      else
        should include("component" => "JOURNAL")
      end

      if ecs_compatibility?
        should include("mongodb" => hash_including("context" => "journal writer"))
      else
        should include("context" => "journal writer")
      end
    end

    it "generates a message field" do
      expect(subject["message"]).to include("Journal writer thread started")
    end

    context '3.6 simple log line' do

      let(:message) do
        '2020-08-13T11:58:09.672+0200 I NETWORK  [conn2] end connection 127.0.0.1:41258 (1 connection now open)'
      end

      it 'matches' do
        should include("timestamp" => "2020-08-13T11:58:09.672+0200")

        if ecs_compatibility?
          should include("mongodb" => hash_including("component" => "NETWORK"))
        else
          should include("component" => "NETWORK")
        end

        if ecs_compatibility?
          should include("mongodb" => hash_including("context" => "conn2"))
        else
          should include("context" => "conn2")
        end

        expect(subject["message"]).to include("end connection 127.0.0.1:41258 (1 connection now open)")
      end

    end

    context '3.6 long log line' do

      let(:command) do
        'command config.$cmd command: createIndexes { createIndexes: "system.sessions", ' +
            'indexes: [ { key: { lastUse: 1 }, name: "lsidTTLIndex", expireAfterSeconds: 1800 } ], $db: "config" } ' +
            'numYields:0 reslen:101 locks:{ Global: { acquireCount: { r: 2, w: 2 } }, Database: { acquireCount: { w: 2 } }, ' +
            'Collection: { acquireCount: { w: 1 } } } protocol:op_msg 0ms'
      end

      let(:message) do
        '2020-08-13T11:57:45.259+0200 I COMMAND  [LogicalSessionCacheRefresh] ' + command
      end

      it 'matches' do
        should include("timestamp" => "2020-08-13T11:57:45.259+0200")

        if ecs_compatibility?
          should include("mongodb" => hash_including("component" => "COMMAND"))
        else
          should include("component" => "COMMAND")
        end

        if ecs_compatibility?
          should include("mongodb" => hash_including("context" => "LogicalSessionCacheRefresh"))
        else
          should include("context" => "LogicalSessionCacheRefresh")
        end

        expect(subject["message"]).to eql [message, command]
      end

    end

  end

  context "parsing a message without context" do

    let(:message) { "2015-04-23T07:00:13.864+0200 I CONTROL  Ctrl-C signal" }

    it 'matches' do
      should include("timestamp" => "2015-04-23T07:00:13.864+0200")

      if ecs_compatibility?
        should include("log" => { 'level' => "I" })
      else
        should include("severity" => "I")
      end

      if ecs_compatibility?
        should include("mongodb" => hash_including("component" => "CONTROL"))
      else
        should include("component" => "CONTROL")
      end

      if ecs_compatibility?
        expect( grok_result['mongodb'].keys ).to_not include("context")
      else
        should_not have_key("context")
      end
    end

    it "generates a message field" do
      expect(subject["message"]).to eql [ message, "Ctrl-C signal" ]
    end
  end
end

describe_pattern "MONGO_SLOWQUERY", ['legacy', 'ecs-v1'] do

  let(:message) do
    "[conn11485496] query sample.User query: { clientId: 12345 } ntoreturn:0 ntoskip:0 nscanned:287011 keyUpdates:0 numYields: 2 locks(micros) r:4187700 nreturned:18 reslen:14019 2340ms"
  end

  it do
    if ecs_compatibility?
      should include("mongodb" => {
          "database" => "sample", "collection" => "User",
          "query" => { "original"=>"{ clientId: 12345 }" },
          "profile" => {
              "op" => "query",
              "ntoreturn" => 0, "ntoskip" => 0, "nscanned" => 287011, "nreturned" => 18,
              "duration" => 2340
          }
      })
    else
      should include("database" => "sample", "collection" => "User")
      should include("ntoreturn" => '0', "ntoskip" => '0', "nscanned" => "287011", "nreturned" => "18")
      should include("query" => "{ clientId: 12345 }")
      should include("duration" => "2340")
    end
  end

end
