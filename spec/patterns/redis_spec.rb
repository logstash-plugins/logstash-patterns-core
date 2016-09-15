# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "REDISTIMESTAMP" do

  let(:value) { '14 Nov 07:01:22.119'}
  let(:pattern) { "REDISTIMESTAMP" }

  it "a pattern pass the grok expression" do
    expect(grok_match(pattern, value)).to pass
  end

end

describe "REDISLOG" do

  let(:value)   { "[4018] 14 Nov 07:01:22.119 * Background saving terminated with success" }
  let(:pattern) { "REDISLOG" }
  let(:grok)    { grok_match(pattern, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "generates the pid field" do
    expect(grok).to include("pid" => "4018")
  end

end


describe "REDISMONLOG - SIMPLE COMMAND" do

  let(:value)   { "1470637867.953466 [0 195.168.1.1:52500] \"info\"" }
  let(:pattern) { "REDISMONLOG" }
  let(:grok)    { grok_match(pattern, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "generates the timestamp field" do
    expect(grok).to include("timestamp" => "1470637867.953466")
  end

  it "generates the database field" do
    expect(grok).to include("database" => "0")
  end

  it "generates the client field" do
    expect(grok).to include("client" => "195.168.1.1")
  end

  it "generates the port field" do
    expect(grok).to include("port" => "52500")
  end

  it "generates the command field" do
    expect(grok).to include("command" => "info")
  end

end

describe "REDISMONLOG - ONE PARAM COMMAND" do

  let(:value)   { "1339518083.107412 [0 127.0.0.1:60866] \"keys\" \"*\"" }
  let(:pattern) { "REDISMONLOG" }
  let(:grok)    { grok_match(pattern, value) }

  it "a pattern pass the grok expression" do
    expect(grok).to pass
  end

  it "generates the timestamp field" do
    expect(grok).to include("timestamp" => "1339518083.107412")
  end

  it "generates the database field" do
    expect(grok).to include("database" => "0")
  end

  it "generates the client field" do
    expect(grok).to include("client" => "127.0.0.1")
  end

  it "generates the port field" do
    expect(grok).to include("port" => "60866")
  end

  it "generates the command field" do
    expect(grok).to include("command" => "keys")
  end

  it "generates the params field" do
    expect(grok).to include("params" => "\"*\"")
  end

end

describe "REDISMONLOG - TWO PARAM COMMAND" do

  let(:value)   { "1470637925.186681 [0 127.0.0.1:39404] \"rpush\" \"my:special:key\" \"{\\\"data\\\":\"cdr\\\",\\\"payload\\\":\\\"json\\\"}\"" }
  let(:pattern) { "REDISMONLOG" }
  let(:grok)    { grok_match(pattern, value) }

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

describe "REDISMONLOG - VARIADIC COMMAND" do

  let(:value)   { "1470637875.777457 [15 195.168.1.1:52500] \"intentionally\" \"broken\" \"variadic\" \"log\" \"entry\"" }
  let(:pattern) { "REDISMONLOG" }
  let(:grok)    { grok_match(pattern, value) }

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