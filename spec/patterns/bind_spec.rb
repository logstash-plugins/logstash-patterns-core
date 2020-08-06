# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "BIND9", ['legacy', 'ecs-v1'] do

  let(:message) do # Bind 9.10
    '17-Feb-2018 23:06:56.326 queries: info: client 172.26.0.1#12345 (test.example.com): query: test.example.com IN A +E(0)K (172.26.0.3)'
  end

  it 'matches' do
    should include("timestamp" => "17-Feb-2018 23:06:56.326")
    if ecs_compatibility?
      should include("log" => hash_including("level" => "info"))
      should include("client" => { "ip" => "172.26.0.1", "port" => 12345 })
      should include("dns" => { "question" => { "name" => "test.example.com", "type" => 'A', "class" => 'IN' }})
      should include("bind" => { "log" => { "question" => hash_including("flags" => '+E(0)K')}})
      should include("server" => { "ip" => "172.26.0.3" })
      # NOTE: duplicate but still captured since we've been doing that before as well :
      should include("bind" => { "log" => { "question" => hash_including("name" => 'test.example.com')}})
    else
      should include("loglevel" => "info")
      should include("clientip" => "172.26.0.1")
      should include("clientport" => "12345")
      should include("query" => ["test.example.com", "test.example.com"])
      should include("querytype" => "A +E(0)K")
      should include("dns" => "172.26.0.3")
    end
  end

  context 'with client memory address (Bind 9.11)' do

    let(:message) do # client @0x7f64500020ef - memory address of the data structure representing the client
      '30-Jun-2018 15:50:00.999 queries: info: client @0x7f64500020ef 192.168.10.48#60061 (91.2.10.170.in-addr.internal): query: 91.2.10.170.in-addr.internal IN PTR + (192.168.2.2)'
    end

    it 'matches' do
      should include("timestamp" => "30-Jun-2018 15:50:00.999")
      if ecs_compatibility?
        should include("log" => hash_including("level" => "info"))
        should include("client" => { "ip" => "192.168.10.48", "port" => 60061 })
        should include("dns" => { "question" => { "name" => "91.2.10.170.in-addr.internal", "type" => 'PTR', "class" => 'IN' }})
        should include("bind" => { "log" => { "question" => hash_including("flags" => '+')}})
        should include("server" => { "ip" => "192.168.2.2" })
      else
        should include("loglevel" => "info")
        should include("clientip" => "192.168.10.48")
        should include("clientport" => "60061")
        should include("query" => ["91.2.10.170.in-addr.internal", "91.2.10.170.in-addr.internal"])
        should include("querytype" => "PTR +")
        should include("dns" => "192.168.2.2")
      end
    end

  end

end
