# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern 'REDISTIMESTAMP', [ 'legacy', 'ecs-v1' ] do

  let(:message) { '14 Nov 07:01:22.119'}

  it "a pattern pass the grok expression" do
    expect(grok_match(pattern, message)).to pass
  end

end

describe_pattern 'REDISLOG', [ 'legacy', 'ecs-v1' ] do

  let(:message) { "[4018] 14 Nov 07:01:22.119 * Background saving terminated with success" }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "generates the pid field" do
    if ecs_compatibility?
      expect(grok).to include("process" => { 'pid' => 4018 })
    else
      expect(grok).to include("pid" => "4018")
    end
  end

end

describe_pattern 'REDISMONLOG', [ 'legacy', 'ecs-v1' ] do

  context "simple command" do

    let(:message) { "1470637867.953466 [0 195.168.1.1:52500] \"info\"" }

    it "a pattern pass the grok expression" do
      expect(grok).to pass
    end

    it "generates the timestamp field" do
      expect(grok).to include("timestamp" => "1470637867.953466")
    end

    it "generates the database field" do
      if ecs_compatibility?
        expect(grok).to include("redis" => hash_including('database' => { 'id' => '0' }))
      else
        expect(grok).to include("database" => "0")
      end
    end

    it "generates the client field" do
      if ecs_compatibility?
        expect(grok).to include("client" => hash_including('ip' => '195.168.1.1'))
      else
        expect(grok).to include("client" => "195.168.1.1")
      end
    end

    it "generates the port field" do
      if ecs_compatibility?
        expect(grok).to include("client" => hash_including('port' => 52500))
      else
        expect(grok).to include("port" => "52500")
      end
    end

    it "generates the command field" do
      if ecs_compatibility?
        expect(grok).to include("redis" => hash_including('command' => { 'name' => 'info' }))
      else
        expect(grok).to include("command" => "info")
      end
    end

  end

  context "one param command" do

    let(:message) { "1339518083.107412 [0 127.0.0.1:60866] \"keys\" \"*\"" }

    it "a pattern pass the grok expression" do
      expect(grok).to pass
    end

    it "generates the timestamp field" do
      expect(grok).to include("timestamp" => "1339518083.107412")
    end

    it "generates the database field" do
      if ecs_compatibility?
        expect(grok).to include("redis" => hash_including('database' => { 'id' => '0' }))
      else
        expect(grok).to include("database" => "0")
      end
    end

    it "generates the client field" do
      if ecs_compatibility?
        expect(grok).to include("client" => hash_including('ip' => '127.0.0.1'))
      else
        expect(grok).to include("client" => "127.0.0.1")
      end
    end

    it "generates the port field" do
      if ecs_compatibility?
        expect(grok).to include("client" => hash_including('port' => 60866))
      else
        expect(grok).to include("port" => "60866")
      end
    end

    it "generates the command field" do
      if ecs_compatibility?
        expect(grok).to include("redis" => hash_including('command' => hash_including('name' => 'keys')))
      else
        expect(grok).to include("command" => "keys")
      end
    end

    it "generates the params field" do
      if ecs_compatibility?
        expect(grok).to include("redis" => hash_including('command' => hash_including('args' => '"*"')))
      else
        expect(grok).to include("params" => "\"*\"")
      end
    end

  end

end

describe_pattern "REDISMONLOG" do

  context 'two param command' do

    let(:message) { "1470637925.186681 [0 127.0.0.1:39404] \"rpush\" \"my:special:key\" \"{\\\"data\\\":\"cdr\\\",\\\"payload\\\":\\\"json\\\"}\"" }

    it "a pattern pass the grok expression" do
      expect(grok).to pass
    end

    it "generates the timestamp field" do
      expect(grok).to include("timestamp" => "1470637925.186681")
    end

    it "generates the database field" do
      expect(grok).to include("database" => "0")
    end

    it "generates the client field" do
      expect(grok).to include("client" => "127.0.0.1")
    end

    it "generates the port field" do
      expect(grok).to include("port" => "39404")
    end

    it "generates the command field" do
      expect(grok).to include("command" => "rpush")
    end

    it "generates the params field" do
      expect(grok).to include("params" => "\"my:special:key\" \"{\\\"data\\\":\"cdr\\\",\\\"payload\\\":\\\"json\\\"}\"")
    end

  end

  context "variadic command" do

    let(:message) { "1470637875.777457 [15 195.168.1.1:52500] \"intentionally\" \"broken\" \"variadic\" \"log\" \"entry\"" }

    it "a pattern pass the grok expression" do
      expect(grok).to pass
    end

    it "generates the timestamp field" do
      expect(grok).to include("timestamp" => "1470637875.777457")
    end

    it "generates the database field" do
      expect(grok).to include("database" => "15")
    end

    it "generates the client field" do
      expect(grok).to include("client" => "195.168.1.1")
    end

    it "generates the port field" do
      expect(grok).to include("port" => "52500")
    end

    it "generates the command field" do
      expect(grok).to include("command" => "intentionally")
    end

    it "generates the params field" do
      expect(grok).to include("params" => "\"broken\" \"variadic\" \"log\" \"entry\"")
    end

  end

end
