# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "BRO_HTTP", ['legacy', 'ecs-v1'] do

  let(:message) do # old BRO logging format
    "1432555199.633017	COpk6E3vkURP8QQNKl	192.168.9.35	55281	178.236.7.146	80	4	POST	www.amazon.it	/xa/dealcontent/v2/GetDeals?nocache=1432555199326	http://www.amazon.it/	Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36	223	1859	200	OK	-	-	-	(empty)	kares	-	-	FrLEcY3AUPKdcYGf29	text/plain	FOJpbGzIMh9syPxH8	text/plain"
  end

  it "matches a simple message" do
    expect(pattern).to match(message)
  end
  
  it "generates the ts field" do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1432555199.633017")
    else
      expect(grok).to include("ts" => "1432555199.633017")
    end
  end

  it "generates the uid field" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("session_id" => "COpk6E3vkURP8QQNKl"))
    else
      expect(grok).to include("uid" => "COpk6E3vkURP8QQNKl")
    end
  end

  it "generates the orig_ fields" do
    if ecs_compatibility?
      expect(grok).to include("source" => { "ip" => "192.168.9.35", "port" => 55281 })
    else
      expect(grok).to include("orig_h" => "192.168.9.35", "orig_p" => "55281")
    end
  end

  it "generates the resp_ fields" do
    if ecs_compatibility?
      expect(grok).to include("destination" => { "ip" => "178.236.7.146", "port" => 80 })

    else
      expect(grok).to include("resp_h" => "178.236.7.146", "resp_p" => "80")
    end
  end

  it "generates the trans_depth field" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("http" => hash_including("trans_depth" => 4)))
    else
      expect(grok).to include("trans_depth" => "4")
    end
  end

  it "generates the method/referrer field" do
    if ecs_compatibility?
      expect(grok).to include("http" => hash_including("request" => hash_including("method" => "POST", "referrer" => "http://www.amazon.it/" )))
    else
      expect(grok).to include("method" => "POST")
      expect(grok).to include("referrer" => "http://www.amazon.it/")
    end
  end

  it "generates the domain/uri/referrer & username/password field" do
    if ecs_compatibility?
      expect(grok).to include("url" => hash_including("domain" => "www.amazon.it"))
      expect(grok).to include("url" => hash_including("original" => "/xa/dealcontent/v2/GetDeals?nocache=1432555199326"))

      expect(grok).to include("url" => hash_including("username" => "kares"))
      expect(grok['url'].keys).to_not include("password")
    else
      expect(grok).to include("domain" => "www.amazon.it")
      expect(grok).to include("uri" => "/xa/dealcontent/v2/GetDeals?nocache=1432555199326")

      expect(grok).to include("username" => "kares")
      expect(grok).to include("password" => "-")
    end
  end

  it "generates the user_agent field" do
    if ecs_compatibility?
      expect(grok).to include("user_agent" => { "original" => "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" })
    else
      expect(grok).to include("user_agent" => "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36")
    end
  end

  it "generates the request_body_len/response_body_len fields" do
    if ecs_compatibility?
      expect(grok).to include("http" => hash_including("request" => hash_including("body" => { "bytes" => 223 })))
      expect(grok).to include("http" => hash_including("response" => hash_including("body" => { "bytes" => 1859 })))
    else
      expect(grok).to include("request_body_len" => "223")
      expect(grok).to include("response_body_len" => "1859")
    end
  end

  it "generates the status_ fields" do
    if ecs_compatibility?
      expect(grok).to include("http" => hash_including("response" => hash_including("status_code" => 200)))
      expect(grok).to include("zeek" => hash_including("http" => hash_including("status_msg" => "OK")))
    else
      expect(grok).to include("status_code" => "200", "status_msg" => "OK")
    end
  end

  it "generates the info_ fields" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("info_code", "info_msg")
    else
      expect(grok).to include("info_code" => "-", "info_msg" => "-")
    end
  end

  it "generates the filename field" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("filename")
    else
      expect(grok).to include("filename" => "-")
    end
  end

  it "generates the bro_tags field" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("tags")
    else
      expect(grok).to include("bro_tags" => "(empty)")
    end
  end

  it "generates the proxied field" do
    if ecs_compatibility?
      expect(grok['zeek']['http'].keys).to_not include("proxied")
    else
      expect(grok).to include("proxied" => "-")
    end
  end

  it "generates the orig_ fields" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("http" => hash_including("orig_fuids" => "FrLEcY3AUPKdcYGf29")))
      expect(grok).to include("zeek" => hash_including("http" => hash_including("orig_mime_types" => "text/plain")))
    else
      expect(grok).to include("orig_fuids" => "FrLEcY3AUPKdcYGf29")
      expect(grok).to include("orig_mime_types" => "text/plain")
    end
  end

  it "generates the resp_ fields" do
    if ecs_compatibility?
      expect(grok).to include("zeek" => hash_including("http" => hash_including("resp_fuids" => "FOJpbGzIMh9syPxH8")))
      expect(grok).to include("zeek" => hash_including("http" => hash_including("resp_mime_types" => "text/plain")))
    else
      expect(grok).to include("resp_fuids" => "FOJpbGzIMh9syPxH8")
      expect(grok).to include("resp_mime_types" => "text/plain")
    end
  end

  context '(zeek) updated log format' do

    let(:message) do # ZEEK
      '1602164975.587600	Ct73QY3M7T5dikxggf	192.168.122.59	55240	93.184.220.29	80	1	-	-	-	-	1.1	-	-	0	471	200	OK	-	-	(empty)	-	-	-	-	-	-	FPGXN33wAFL8MPKJXl	-	application/ocsp-response'
    end

    it 'matches in legacy mode' do
      unless ecs_compatibility? # wrong but backwards compatibility
        expect(grok).to include("domain" => "1.1") # due GREEDYDATA: "method" => "-\t-\t-\t-"
      end
    end

    it 'no longer matches in ecs mode' do
      expect(grok['tags']).to include("_grokparsefailure") if ecs_compatibility?
    end

  end

end

describe_pattern "ZEEK_HTTP", ['ecs-v1'] do

  context "long message" do

    let(:message) do
      "1333458850.375568	ClEkJM2Vm5giqnMf4h	10.131.47.185	1923	79.101.110.141	80	1	GET	o-o.preferred.telekomrs-beg1.v2.lscache8.c.youtube.com	/videoplayback?upn=MTU2MDY5NzQ5OTM0NTI3NDY4NDc&sparams=algorithm,burst,cp,factor,id,ip,ipbits,itag,source,upn,expire&fexp=912300,907210&algorithm=throttle-factor&itag=34&ip=212.0.0.0&burst=40&sver=3&signature=832FB1042E20780CFCA77A4DB5EA64AC593E8627.D1166C7E8365732E52DAFD68076DAE0146E0AE01&source=youtube&expire=1333484980&key=yt1&ipbits=8&factor=1.25&cp=U0hSSFRTUl9NSkNOMl9MTVZKOjh5eEN2SG8tZF84&id=ebf1e932d4bd1286&cm2=1	http://s.ytimg.com/yt/swfbin/watch_as3-vflqrJwOA.swf	1.1	Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko; X-SBLSP) Chrome/17.0.963.83 Safari/535.11	-	0	56320	206	Partial Content	-	-	(empty)	-	-	-	-	-	-	FpmJd62pFQcZ3gcUgl	-	-"
    end

    it "matches" do
      expect(grok).to include("timestamp"=>"1333458850.375568")
      expect(grok).to include("zeek" => hash_including("session_id"=>"ClEkJM2Vm5giqnMf4h"))
      expect(grok).to include("http" => {
          "response" => { "body" =>{ "bytes" => 56320 }, "status_code"=>206 },
          "request" => { "body" => { "bytes" => 0 }, "referrer"=>"http://s.ytimg.com/yt/swfbin/watch_as3-vflqrJwOA.swf", "method"=>"GET"},
          "version"=>"1.1"
      })
      expect(grok).to include("user_agent"=>{"original"=>"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko; X-SBLSP) Chrome/17.0.963.83 Safari/535.11"})
      expect(grok).to include("url"=>{
          "domain"=>"o-o.preferred.telekomrs-beg1.v2.lscache8.c.youtube.com",
          "original"=>"/videoplayback?upn=MTU2MDY5NzQ5OTM0NTI3NDY4NDc&sparams=algorithm,burst,cp,factor,id,ip,ipbits,itag,source,upn,expire&fexp=912300,907210&algorithm=throttle-factor&itag=34&ip=212.0.0.0&burst=40&sver=3&signature=832FB1042E20780CFCA77A4DB5EA64AC593E8627.D1166C7E8365732E52DAFD68076DAE0146E0AE01&source=youtube&expire=1333484980&key=yt1&ipbits=8&factor=1.25&cp=U0hSSFRTUl9NSkNOMl9MTVZKOjh5eEN2SG8tZF84&id=ebf1e932d4bd1286&cm2=1"
      })
      expect(grok).to include("destination"=>{"port"=>80, "ip"=>"79.101.110.141"}, "source"=>{"port"=>1923, "ip"=>"10.131.47.185"})
      expect(grok).to include("zeek" => hash_including("http"=>{"resp_fuids"=>"FpmJd62pFQcZ3gcUgl", "status_msg"=>"Partial Content", "trans_depth"=>1}))
    end

  end

  context "sample message" do

    let(:message) do
      "1602165002.455618	CWGOypTfRypTC5C4g	192.168.122.59	44136	216.58.201.110	80	1	-	-	-	-	1.1	Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0	https://example.com	0	219	301	Moved Permanently	-	-	FOO,BAR	-	-	-	-	-	-	FeJ7iiVorMXoLlRK	-	text/html"
    end

    it "matches" do
      expect(grok).to include("timestamp"=>"1602165002.455618")
      expect(grok).to include("user_agent"=>{"original"=>"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0"})
      expect(grok).to include("http" => {
          "request" => { "body" => {"bytes" => 0 } },
          "response" => { "status_code" => 301, "body" =>{ "bytes" => 219 } },
          "version"=>"1.1"
      })
      expect(grok).to include("zeek" => {
          "session_id" => "CWGOypTfRypTC5C4g",
          "http" => {
              "trans_depth"=>1,
              "origin"=>"https://example.com",
              "tags"=>"FOO,BAR",
              "resp_mime_types"=>"text/html",
              "status_msg"=>"Moved Permanently",
              "resp_fuids"=>"FeJ7iiVorMXoLlRK"}
      })
    end

  end

  context 'old (bro) message' do

    let(:message) do
      "1432555199.633017	COpk6E3vkURP8QQNKl	192.168.9.35	55281	178.236.7.146	80	4	POST	www.amazon.it	/xa/dealcontent/v2/GetDeals?nocache=1432555199326	http://www.amazon.it/	Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36	223	1859	200	OK	-	-	-	(empty)	kares	-	-	FrLEcY3AUPKdcYGf29	text/plain	FOJpbGzIMh9syPxH8	text/plain"
    end

    it 'does not match' do
      expect(grok['tags']).to include("_grokparsefailure") if ecs_compatibility?
    end

  end

  context 'old empty (bro) message' do

    let(:message) do # theoretically everything except these is optional:
      "1432555199.633017	COpk6E3vkURP8QQNKl	192.168.9.35	55281	178.236.7.146	80	0	-	-	-	-	-	-	-	-	-	-	-	-	(empty)	-	-	-	-	-	-	-"
    end

    it 'does not match' do
      expect(grok['tags']).to include("_grokparsefailure") if ecs_compatibility?
    end

  end

end

describe_pattern 'BRO_DNS', ['legacy', 'ecs-v1'] do

  let(:message) do # old BRO logging format
    "1359565680.761790	UWkUyAuUGXf	192.168.6.10	53209	192.168.129.36	53	udp	41477	paypal.com	1	C_INTERNET	48	DNSKEY	0	NOERROR	F	F	T	F	1	-	-	F"
  end

  it 'matches' do
    if ecs_compatibility?
      expect(grok).to include("timestamp" => "1359565680.761790")
      expect(grok).to include("zeek" => hash_including("session_id" => "UWkUyAuUGXf"))
      expect(grok).to include("source" => { "ip"=>"192.168.6.10", "port"=>53209 }, "destination" => { "ip"=>"192.168.129.36", "port"=>53 })
      expect(grok).to include("network" => { "transport" => "udp" })
      expect(grok).to include("dns" => {
          "id" => 41477,
          "question" => { "name" => "paypal.com", "type" => "DNSKEY" },
          "response_code" => "NOERROR",
      })
      expect(grok['zeek']).to include("dns" => hash_including("qclass" => 1, "qclass_name" => "C_INTERNET"))
      expect(grok['zeek']).to include("dns" => hash_including("qtype" => 48)) # beats compatibility
      expect(grok['zeek']).to include("dns" => hash_including("rcode" => 0)) # beats compatibility
      # TODO :bool type-casting would be nice
      expect(grok['zeek']).to include("dns" => hash_including("AA"=>"F", "TC"=>"F", "RD"=>"T", "RA"=>"F"))
      expect(grok['zeek']).to include("dns" => hash_including("Z" => 1)) # beats drops this field
      expect(grok['zeek']).to include("dns" => hash_including("rejected" => "F"))
      expect(grok['zeek']['dns'].keys).to_not include 'TTLs', 'answers'
    else
      expect(grok).to include(
                          "ts"=>"1359565680.761790", "uid"=>"UWkUyAuUGXf",
                          "orig_h"=>"192.168.6.10", "orig_p"=>"53209",
                          "resp_h" => "192.168.129.36", "resp_p"=>"53",
                          "proto"=>"udp",
                          "trans_id"=>"41477",
                          "query"=>"paypal.com",
                          "qclass"=>"1", "qclass_name"=>"C_INTERNET",
                          "qtype"=>"48", "qtype_name"=>"DNSKEY",
                          "rcode"=>"0", "rcode_name"=>"NOERROR",
                          "AA"=>"F", "TC"=>"F",
                          "RD"=>"T", "RA"=>"F",
                          "Z"=>"1",
                          "answers"=>"-",
                          "TTLs"=>"-",
                          "rejected"=>"F",
                          )
    end
  end

  context 'optional fields' do

    let(:message) do
      "1359565680.761790	UWkUyAuUGXf	192.168.6.10	53209	192.168.129.36	53	udp	-	-	-	-	-	-	-	-	F	F	F	F	0	-	-	-"
      # AA/TC/RD/RA are optional with a F default, Z is optional with a 0 default
    end

    it 'matches (only) fields present' do
      if ecs_compatibility?
        expect(grok).to include("timestamp" => "1359565680.761790")
        expect(grok).to include("source" => { "ip"=>"192.168.6.10", "port"=>53209 }, "destination" => { "ip"=>"192.168.129.36", "port"=>53 })
        expect(grok).to include("network" => { "transport"=>"udp" })
        expect(grok).to include("zeek" => { "session_id" => "UWkUyAuUGXf", "dns" => { "AA"=>"F", "TC"=>"F", "RD"=>"F", "RA"=>"F", "Z"=>0 } })
        expect(grok.keys).to_not include('dns')
      end
    end

  end

  context '(zeek) updated log format' do

    let(:message) do
      "1359565680.761790	CHhAvVGS1DHFjwGM9	192.168.6.10	53209	192.168.129.36	53	udp	41477	0.075138	paypal.com	1	C_INTERNET	48	DNSKEY	0	NOERROR	F	F	T	T	1	DNSKEY 5,DNSKEY 5,RRSIG 48 paypal.com,RRSIG 48 paypal.com	455.000000,455.000000,455.000000,455.000000	F"
    end

    it 'no longer matches in ecs mode' do
      expect(grok['tags']).to include("_grokparsefailure") if ecs_compatibility?
    end

  end

end

describe_pattern "ZEEK_DNS", ['ecs-v1'] do

  let(:message) do
    "1359565680.761790	CHhAvVGS1DHFjwGM9	192.168.6.10	53209	192.168.129.36	53	udp	41477	0.075138	paypal.com	1	C_INTERNET	48	DNSKEY	0	NOERROR	F	F	T	T	1	DNSKEY 5,DNSKEY 5,RRSIG 48 paypal.com,RRSIG 48 paypal.com	455.000000,455.000000,455.000000,455.000000	F"
  end

  it 'matches' do
    expect(grok).to include("timestamp" => "1359565680.761790")
    expect(grok).to include("destination"=>{"ip"=>"192.168.129.36", "port"=>53}, "source"=>{"ip"=>"192.168.6.10", "port"=>53209})
    expect(grok).to include("network" => {"transport"=>"udp"})
    expect(grok).to include("dns"=>{"question"=>{"type"=>"DNSKEY", "name"=>"paypal.com"}, "response_code"=>"NOERROR", "id"=>41477})
    expect(grok).to include("zeek"=>{
        "session_id"=>"CHhAvVGS1DHFjwGM9",
        "dns"=>{
            "rtt" => 0.075138 ,
            "qclass"=>1, "qclass_name"=>"C_INTERNET", "qtype"=>48,
            "rcode"=>0,
            "RA"=>"T", "RD"=>"T", "TC"=>"F", "rejected"=>"F", "AA"=>"F", "Z"=>1,
            "answers"=>"DNSKEY 5,DNSKEY 5,RRSIG 48 paypal.com,RRSIG 48 paypal.com",
            "TTLs"=>"455.000000,455.000000,455.000000,455.000000"
        }
    })
  end

end

describe_pattern 'BRO_CONN', ['legacy', 'ecs-v1'] do

  let(:message) do
    "1541350796.901974	C54zqz17PXuBv3HkLg	192.168.0.26	54855	54.85.115.89	443	tcp	ssl	0.153642	1147	589	SF	T	0	ShADadfF	7	1439	8	921	(empty)"
  end

  it 'matches' do
    if ecs_compatibility?
      expect(grok).to include("timestamp"=>"1541350796.901974")
      expect(grok).to include("zeek" => hash_including("session_id" => "C54zqz17PXuBv3HkLg"))
      expect(grok).to include("network"=>{"transport"=>"tcp", "protocol"=>"ssl"})
      expect(grok).to include("source"=>{
          "ip"=>"192.168.0.26", "port"=>54855,
          "packets"=>7, "bytes"=>1439
      })
      expect(grok).to include("destination"=>{
          "ip"=>"54.85.115.89", "port"=>443,
          "packets"=>8, "bytes"=>921
      })
      expect(grok).to include("zeek" => hash_including(
          "connection" => {
              "duration"=>0.153642,
              "orig_bytes"=>1147, "resp_bytes"=>589,
              "state"=>"SF",
              "local_orig"=>"T", "missed_bytes"=>0,
              "history"=>"ShADadfF",
          }
      ))
    else
      expect(grok).to include(
                          "ts"=>"1541350796.901974", "uid"=>"C54zqz17PXuBv3HkLg",
                          "orig_h"=>"192.168.0.26", "orig_p"=>"54855",
                          "resp_h" => "54.85.115.89", "resp_p"=>"443",
                          "proto"=>"tcp",
                          "service"=>"ssl",
                          "duration"=>"0.153642",
                          "orig_bytes"=>"1147", "resp_bytes"=>"589",
                          "conn_state"=>"SF",
                          "local_orig"=>"T",
                          "missed_bytes"=>"0",
                          "history"=>"ShADadfF",
                          "orig_pkts"=>"7", "orig_ip_bytes"=>"1439",
                          "resp_pkts"=>"8", "resp_ip_bytes"=>"921",
                          "tunnel_parents"=>"(empty)",
                          )
    end
  end

  context 'updated log format' do # up to version 3.3
    let(:message) do
      "1300475168.853899	C4J4Th3PJpwUYZZ6gc	141.142.220.118	43927	141.142.2.2	53	udp	dns	0.000435	38	89	SF	-	-	0	Dd	1	66	1	117	(empty)"
    end

    it 'matches' do
      if ecs_compatibility?
        expect(grok).to include("zeek" => hash_including("session_id" => "C4J4Th3PJpwUYZZ6gc"))
        expect(grok).to include("network"=>{"transport"=>"udp", "protocol"=>"dns"})
        expect(grok).to include("source"=>{
            "ip"=>"141.142.220.118", "port"=>43927,
            "packets"=>1, "bytes"=>66
        })
        expect(grok).to include("destination"=>{
            "ip"=>"141.142.2.2", "port"=>53,
            "packets"=>1, "bytes"=>117
        })
        expect(grok).to include("zeek" => hash_including(
            "connection" => {
                "duration"=>0.000435,
                "orig_bytes"=>38, "resp_bytes"=>89,
                "state"=>"SF",
                "missed_bytes"=>0,
                "history"=>"Dd",
            }
        ))
      else
        expect(grok).to include("ts"=>"1300475168.853899")
        expect(grok).to include("conn_state"=>"SF\t-") # matches incorrectly
      end
    end
  end

end

describe_pattern 'ZEEK_CONN', ['ecs-v1'] do

  let(:message) do
    "1602165198.216970	CfVl4yNLJ4U3ptL12	192.168.122.59	47340	143.204.201.102	443	tcp	-	115.669583	0	6238	SHR	T	F	0	^hCadcCfA	1	52	21	5091	-"
  end

  it 'matches' do
    expect(grok).to include("timestamp" => "1602165198.216970")
    expect(grok).to include("network" => { "transport" => "tcp" })
    expect(grok).to include("source" => { "ip"=>"192.168.122.59", "port"=>47340, "packets"=>1, "bytes"=>52 })
    expect(grok).to include("destination" => { "ip"=>"143.204.201.102", "port"=>443, "packets"=>21, "bytes"=>5091 })

    expect(grok).to include("zeek"=>{
        "connection"=>{
            "duration"=>115.669583,
            "orig_bytes"=>0,
            "resp_bytes"=>6238,
            "state"=>"SHR",
            "local_orig"=>"T",
            "local_resp"=>"F",
            "missed_bytes"=>0,
            "history"=>"^hCadcCfA"
        },
        "session_id"=>"CfVl4yNLJ4U3ptL12"
    })
  end

  context 'with mac adresses' do

    let(:message) do
      "1128727435.633408	CHhAvVGS1DHFjwGM9	141.42.64.125	56730	125.190.109.199	80	tcp	http	1.550793	98	9417	SF	-	-	0	^hADdFaf	11	670	10	9945	-	00:d0:03:3b:f4:00	00:b0:c2:86:ec:00"
    end

    it 'matches' do
      expect(grok).to include("timestamp" => "1128727435.633408")
      expect(grok).to include("zeek" => hash_including("session_id" => "CHhAvVGS1DHFjwGM9"))
      expect(grok).to include("network" => { "transport" => "tcp", "protocol" => "http" })
      expect(grok).to include("source" => { "mac"=>"00:d0:03:3b:f4:00", "ip"=>"141.42.64.125", "port"=>56730, "packets"=>11, "bytes"=>670 })
      expect(grok).to include("destination" => { "mac"=>"00:b0:c2:86:ec:00", "ip"=>"125.190.109.199", "port"=>80, "packets"=>10, "bytes"=>9945 })

      expect(grok).to include("zeek"=>hash_including("connection" => hash_including("duration"=>1.550793)))
    end

  end

end

describe_pattern 'BRO_FILES', ['legacy', 'ecs-v1'] do

  let(:message) do
    "1362692527.009512	FakNcS1Jfe01uljb3	192.150.187.43	141.142.228.5	CXWv6p3arKYeMETxOg	HTTP	0	MD5,SHA1	text/plain	-	0.000263	-	F	4705	4705	0	0	F	-	397168fd09991a0e712254df7bc639ac	1dd7ac0398df6cbc0696445a91ec681facf4dc47	-	-"
  end

  it 'matches' do
    if ecs_compatibility?
      expect(grok).to include("timestamp"=>"1362692527.009512")
      expect(grok).to include("zeek"=>{ "files" => {
          "fuid"=>"FakNcS1Jfe01uljb3",
          "tx_host"=>"192.150.187.43", "rx_host"=>"141.142.228.5",
          "session_ids"=>"CXWv6p3arKYeMETxOg",
          "source"=>"HTTP", "depth"=>0, "analyzers"=>"MD5,SHA1",
          "duration"=>0.000263,
          "is_orig"=>"F",
          "overflow_bytes"=>0, "missing_bytes"=>0, "seen_bytes"=>4705,
          "timedout"=>"F"
      }})
      expect(grok).to include("file"=>{
          "size"=>4705, "mime_type"=>"text/plain",
          "hash"=>{"sha1"=>"1dd7ac0398df6cbc0696445a91ec681facf4dc47", "md5"=>"397168fd09991a0e712254df7bc639ac"}
      })
    else
      expect(grok).to include("ts"=>"1362692527.009512", "fuid"=>"FakNcS1Jfe01uljb3")
      expect(grok).to include("tx_hosts"=>"192.150.187.43", "rx_hosts"=>"141.142.228.5")
      expect(grok).to include("conn_uids"=>"CXWv6p3arKYeMETxOg")
      expect(grok).to include("source"=>"HTTP", "depth"=>"0", "analyzers"=>"MD5,SHA1", "mime_type"=>"text/plain")
      expect(grok).to include("filename"=>"-")
      expect(grok).to include("duration"=>"0.000263")
      expect(grok).to include("local_orig"=>"-", "is_orig"=>"F",
                              "seen_bytes"=>"4705", "total_bytes"=>"4705", "missing_bytes"=>"0", "overflow_bytes"=>"0",
                              "timedout"=>"F",
                              "parent_fuid"=>"-",
                              "md5"=>"397168fd09991a0e712254df7bc639ac", "sha1"=>"1dd7ac0398df6cbc0696445a91ec681facf4dc47", "sha256"=>"-",
                              "extracted"=>"-"
      )
    end
  end

  context 'new (zeek) message format' do

    let(:message) do
      "1602576142.884704	Frp9wcpqbDl991Zh7	151.101.112.204	192.168.122.59	C3v3ce39xvI63Tn2E5	HTTP	0	SHA1,MD5	text/plain	-	0.000000	F	F	3707	51901	0	0	F	-	995875a72487a52a657b94e3857ac4fe	00c45f6771d0006029a8ced68bf2a41ca3060e69	-	-	-	-"
    end

    it 'matches (incorrectly) in legacy mode' do
      unless ecs_compatibility?
        expect(grok).to include("ts"=>"1602576142.884704", "fuid"=>"Frp9wcpqbDl991Zh7")
        expect(grok).to include("source"=>"HTTP\t0\tSHA1,MD5") # BOGUS
      end
    end

    it '~~does not match in ecs mode~~ matches (correctly) in ECS mode' do # since new format changes are additions at the end
      if ecs_compatibility?
        expect(grok).to include("timestamp"=>"1602576142.884704")
        expect(grok).to include("zeek"=>{"files"=>{
            "fuid"=>"Frp9wcpqbDl991Zh7",
            "tx_host"=>"151.101.112.204", "rx_host"=>"192.168.122.59",
            "session_ids"=>"C3v3ce39xvI63Tn2E5",
            "source"=>"HTTP", "depth"=>0, "analyzers"=>"SHA1,MD5",
            "duration"=>0.0,
            "local_orig"=>"F", "is_orig"=>"F",
            "missing_bytes"=>0,
            "timedout"=>"F",
            "overflow_bytes"=>0, "seen_bytes"=>3707
        }})
        expect(grok).to include("file"=>{
            "size"=>51901, "mime_type"=>"text/plain",
            "hash"=>{"md5"=>"995875a72487a52a657b94e3857ac4fe", "sha1"=>"00c45f6771d0006029a8ced68bf2a41ca3060e69"}
        })
      end
    end

  end

end

describe_pattern 'ZEEK_FILES', ['ecs-v1'] do

  let(:message) do
    "1258867934.558264	F2xow8TIkvHG4Zz41	198.189.255.75	192.168.1.105	CHhAvVGS1DHFjwGM9	HTTP	0	EXTRACT	-	-	0.046240	-	F	54229	605292323	4244449	0	T	-	-	-	-	extract-1258867934.558264-HTTP-F2xow8TIkvHG4Zz41	T	4000"
  end

  it 'matches' do
    expect(grok).to include("timestamp"=>"1258867934.558264")
    expect(grok).to include("server"=>{"ip"=>'198.189.255.75'}) # tx_host
    expect(grok).to include("client"=>{"ip"=>'192.168.1.105'}) # rx_host
    expect(grok).to include("zeek"=>{"files"=>hash_including(
        "fuid"=>"F2xow8TIkvHG4Zz41",
        "session_ids"=>"CHhAvVGS1DHFjwGM9",
        "source"=>"HTTP", "analyzers"=>"EXTRACT",
        "timedout"=>"T",

        "extracted"=>"extract-1258867934.558264-HTTP-F2xow8TIkvHG4Zz41",
        "extracted_size"=>4000, "extracted_cutoff"=>"T"
        )})
    expect(grok).to include("file"=>{"size"=>605292323})
  end

  context 'multiple hosts' do

    let(:message) do
      # NOTE: Zeek sometimes treats set[ip/string] types as ',' separated other times as ' ' separated
      "1258867934.558264	F2xow8TIkvHG4Zz41	10.1.1.2 10.1.1.1	192.168.1.105,192.168.1.10,192.168.1.11	-	-	0	-	-	-	0.01234	-	F	-	-	-	0	T	-	-	-	-	-	-	-"
    end

    it 'matches host(s)' do
      expect(grok).to include("server"=>{"ip" => '10.1.1.2'}) # tx_host
      expect(grok).to include("client"=>{"ip" => '192.168.1.105'}) # rx_host
      expect(grok).to include("zeek"=>{"files" => hash_including("tx_hosts" => '10.1.1.2 10.1.1.1')})
      expect(grok).to include("zeek"=>{"files" => hash_including("rx_hosts" => '192.168.1.105,192.168.1.10,192.168.1.11')})
    end

  end

end
