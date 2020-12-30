# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "JAVACLASS" do
  let(:example) { 'hudson.node_monitors.AbstractAsyncNodeMonitorDescriptor' }
  it "matches a java class with underscores" do
    expect(grok_match(subject, example, true)['tags']).to be_nil
  end
end
describe "JAVAFILE" do
  let(:example) { 'Native Method' }
  it "matches a java file name with spaces" do
    expect(grok_match(subject, example, true)['tags']).to be_nil
  end
end

describe_pattern "JAVASTACKTRACEPART", [ 'legacy', 'ecs-v1' ] do
  let(:message) { '  at com.sample.stacktrace.StackTraceExample.aMethod(StackTraceExample.java:42)' }

  it "matches" do
    if ecs_compatibility?
      expect(subject).to include(
                          "log" => { "origin" => { "function" => 'aMethod', "file" => { "name" => 'StackTraceExample.java', "line" => 42 } } },
                          "java" => { "log" => { "origin" => { "class" => { "name" => 'com.sample.stacktrace.StackTraceExample' } } } }
                      )
    else
      expect(subject).to include(
                          "message"=>"  at com.sample.stacktrace.StackTraceExample.aMethod(StackTraceExample.java:42)",
                          "method"=>"aMethod",
                          "class"=>"com.sample.stacktrace.StackTraceExample",
                          "file"=>"StackTraceExample.java",
                          "line"=>"42"
                      )
    end
  end

  context 'generated file' do
    let(:message) { '  at org.jruby.RubyMethod$INVOKER$i$call.call(RubyMethod$INVOKER$i$call.gen)' }
    it "matches" do
      if ecs_compatibility?
        expect(subject).to include(
                               "log"=>{"origin"=>{"function"=>"call", "file"=>{"name"=>"RubyMethod$INVOKER$i$call.gen"}}},
                               "java"=>{"log"=>{"origin"=>{"class"=>{"name"=>"org.jruby.RubyMethod$INVOKER$i$call"}}}}
                           )
      else
        expect(subject).to include({
                                    "method"=>"call",
                                    "class"=>"org.jruby.RubyMethod$INVOKER$i$call",
                                    "file"=>"RubyMethod$INVOKER$i$call.gen",
                                })
      end
    end
  end

end

describe_pattern "CATALINALOG", [ 'legacy', 'ecs-v1' ] do

  context 'Tomcat 4.1' do

    let(:message) do
      "Dec 30, 2020 11:30:40 AM org.apache.struts.util.PropertyMessageResources <init>\n" +
          "INFO: Initializing, config='org.apache.struts.util.LocalStrings', returnNull=true"
    end

    it "matches" do
      expect(subject).to include "timestamp"=>"Dec 30, 2020 11:30:40 AM"
      if ecs_compatibility?
        expect(subject).to include "java"=>{"log"=>{"origin"=>{"class"=>{"name"=>"org.apache.struts.util.PropertyMessageResources"}}}},
                                   "log"=>{"level"=>"INFO", "origin"=>{"function"=>"<init>"}}

        expect(subject).to include "message"=>[message, "Initializing, config='org.apache.struts.util.LocalStrings', returnNull=true"]
      else
        expect(subject).to include "class"=>"org.apache.struts.util.PropertyMessageResources",
                                   "logmessage"=>"<init>\nINFO: Initializing, config='org.apache.struts.util.LocalStrings', returnNull=true"
      end
    end

  end

  context 'Tomcat 6.0' do # ~ same for Tomcat 4.x - 7.x

    let(:message) do
      "Jul 30, 2020 3:00:21 PM org.apache.coyote.http11.Http11Protocol init\nINFO: Initializing Coyote HTTP/1.1 on http-8080"
    end

    it "matches" do
      expect(subject).to include "timestamp"=>"Jul 30, 2020 3:00:21 PM"
      if ecs_compatibility?
        expect(subject).to include "java"=>{"log"=>{"origin"=>{"class"=>{"name"=>"org.apache.coyote.http11.Http11Protocol"}}}},
                                   "log"=>{"level"=>"INFO", "origin"=>{"function"=>"init"}}

        expect(subject).to include "message"=>[message, "Initializing Coyote HTTP/1.1 on http-8080"]
      else
        expect(subject).to include "class"=>"org.apache.coyote.http11.Http11Protocol",
                                   "logmessage" => "init\nINFO: Initializing Coyote HTTP/1.1 on http-8080"
      end
    end

  end

  context 'Tomcat 9.0' do # same for Tomcat 8.5

    let(:message) do
      "31-Jul-2020 16:40:38.505 INFO [localhost-startStop-1] org.apache.catalina.startup.HostConfig.deployDirectory " +
          "Deployment of web application directory [/opt/temp/apache-tomcat-8.5.57/webapps/ROOT] has finished in [40] ms"
    end

    it "matches" do
      if ecs_compatibility?
        expect(subject).to include "timestamp"=>"31-Jul-2020 16:40:38.505"

        expect(subject).to include "java"=>{"log"=>{"origin"=>{
                                      "thread"=>{"name"=>"localhost-startStop-1"},
                                      "class"=>{"name"=>"org.apache.catalina.startup.HostConfig"}}}},
                                   "log"=>{"level"=>"INFO", "origin"=>{"function"=>"deployDirectory"}}

        expect(subject).to include "message"=>[message, "Deployment of web application directory [/opt/temp/apache-tomcat-8.5.57/webapps/ROOT] has finished in [40] ms"]
      else
        # not supported in legacy mode
      end
    end

  end

  context 'multiline stack-trace' do

  let(:message) do
<<LINE
30-Dec-2020 11:44:31.277 SEVERE [main] org.apache.catalina.util.LifecycleBase.handleSubClassException Failed to initialize component [Connector[HTTP/1.1-8080]]
	org.apache.catalina.LifecycleException: Protocol handler initialization failed
		at org.apache.catalina.connector.Connector.initInternal(Connector.java:1042)
		at org.apache.catalina.util.LifecycleBase.init(LifecycleBase.java:136)
		at org.apache.catalina.core.StandardService.initInternal(StandardService.java:533)
		at org.apache.catalina.util.LifecycleBase.init(LifecycleBase.java:136)
		at org.apache.catalina.core.StandardServer.initInternal(StandardServer.java:1057)
		at org.apache.catalina.util.LifecycleBase.init(LifecycleBase.java:136)
		at org.apache.catalina.startup.Catalina.load(Catalina.java:690)
		at org.apache.catalina.startup.Catalina.load(Catalina.java:712)
		at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
		at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
		at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
		at java.lang.reflect.Method.invoke(Method.java:498)
		at org.apache.catalina.startup.Bootstrap.load(Bootstrap.java:302)
		at org.apache.catalina.startup.Bootstrap.main(Bootstrap.java:472)
	Caused by: java.net.BindException: Address already in use
		at sun.nio.ch.Net.bind0(Native Method)
		at sun.nio.ch.Net.bind(Net.java:433)
		at sun.nio.ch.Net.bind(Net.java:425)
		at sun.nio.ch.ServerSocketChannelImpl.bind(ServerSocketChannelImpl.java:223)
		at sun.nio.ch.ServerSocketAdaptor.bind(ServerSocketAdaptor.java:74)
		at org.apache.tomcat.util.net.NioEndpoint.initServerSocket(NioEndpoint.java:228)
		at org.apache.tomcat.util.net.NioEndpoint.bind(NioEndpoint.java:211)
		at org.apache.tomcat.util.net.AbstractEndpoint.bindWithCleanup(AbstractEndpoint.java:1141)
		at org.apache.tomcat.util.net.AbstractEndpoint.init(AbstractEndpoint.java:1154)
		at org.apache.coyote.AbstractProtocol.init(AbstractProtocol.java:581)
		at org.apache.coyote.http11.AbstractHttp11Protocol.init(AbstractHttp11Protocol.java:74)
		at org.apache.catalina.connector.Connector.initInternal(Connector.java:1039)
		... 13 more
LINE
  end

  it "matches" do
    if ecs_compatibility?
      expect(subject).to include "timestamp"=>"30-Dec-2020 11:44:31.277"

      expect(subject).to include "java"=>{"log"=>{"origin"=>{
                                    "thread"=>{"name"=>"main"},
                                    "class"=>{"name"=>"org.apache.catalina.util.LifecycleBase"}}}},
                                 "log"=>{"level"=>"SEVERE", "origin"=>{"function"=>"handleSubClassException"}}

      expect(subject['message'][0]).to eql message
      expect(subject['message'][1]).to start_with 'Failed to initialize component [Connector[HTTP/1.1-8080]]'
    else
      # not supported in legacy mode
    end
  end

  end

end

describe_pattern "TOMCATLOG", [ 'legacy', 'ecs-v1' ] do

  context 'example format' do

    let(:message) do
      '2014-01-09 20:03:28,269 -0800 | ERROR | com.example.service.ExampleService - something compeletely unexpected happened...'
    end

    it "matches" do
      expect(subject).to include "timestamp"=>"2014-01-09 20:03:28,269 -0800"
      if ecs_compatibility?
        expect(subject).to include "log"=>{"level"=>"ERROR"},
                                   "java"=>{"log"=>{"origin"=>{"class"=>{"name"=>"com.example.service.ExampleService"}}}}
      else
        expect(subject).to include "level"=>"ERROR"
      end
    end

    it "'generates' the message field" do
      if ecs_compatibility?
        expect(subject).to include "message"=>[message, "something compeletely unexpected happened..."]
      else
        expect(subject).to include("logmessage" => "something compeletely unexpected happened...")
      end
    end

  end

end