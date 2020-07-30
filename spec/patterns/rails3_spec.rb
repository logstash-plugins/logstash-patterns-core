# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "RAILS3", ['legacy', 'ecs-v1'] do

  context "single-line log" do

    let(:message) { 'Started POST "/api/v3/internal/allowed" for 127.0.0.1 at 2015-08-05 11:37:01 +0200' }

    # Started
    it do
      if ecs_compatibility?
        should include("http" => hash_including("request" => { "method" => "POST" }))
      else
        should include("verb" => "POST")
      end
    end

    it do
      if ecs_compatibility?
      else
        should include("request" => "/api/v3/internal/allowed")
      end
    end
    # for
    it do
      if ecs_compatibility?
        should include("source" => { "address" => "127.0.0.1" })
      else
        should include("clientip" => "127.0.0.1")
      end
    end
    # at
    it { should include("timestamp" => "2015-08-05 11:37:01 +0200" ) }
  end

  context "multi-line log" do

    let(:message) { 'Started GET "/puppet/postfix/notes?target_id=162&target_type=issue&last_fetched_at=1438695732" for 127.0.0.1 at 2015-08-05 07:40:22 +0200
Processing by Projects::NotesController#index as JSON
  Parameters: {"target_id"=>"162", "target_type"=>"issue", "last_fetched_at"=>"1438695732", "namespace_id"=>"puppet", "project_id"=>"postfix"}
Completed 200 OK in 640ms (Views: 1.7ms | ActiveRecord: 91.0ms)' }

    # started
    it do
      if ecs_compatibility?
        should include("http" => hash_including("request" => { "method" => "GET" }))
      else
        should include("verb" => "GET")
      end
    end

    it do
      if ecs_compatibility?
        should include("url" => {"original"=>"/puppet/postfix/notes?target_id=162&target_type=issue&last_fetched_at=1438695732"})
      else
        should include("request" => "/puppet/postfix/notes?target_id=162&target_type=issue&last_fetched_at=1438695732" )
      end
    end
    # for
    it do
      if ecs_compatibility?
        should include("source" => { "address" => "127.0.0.1" })
      else
        should include("clientip" => "127.0.0.1")
      end
    end
    # at
    it { should include("timestamp" => "2015-08-05 07:40:22 +0200") }
    # Processing by
    it do
      if ecs_compatibility?
        should include("rails" => hash_including("controller" => { "class"=>"Projects::NotesController", "action"=>"index" }))
      else
        should include("controller" => "Projects::NotesController")
        should include("action" => "index")
      end
    end
    # as
    it do
      if ecs_compatibility?
        should include("rails" => hash_including("request" => hash_including("format" => 'JSON')))
      else
        should include("format" => "JSON" )
      end
    end
    # Parameters
    it do
      params = '"target_id"=>"162", "target_type"=>"issue", "last_fetched_at"=>"1438695732", "namespace_id"=>"puppet", "project_id"=>"postfix"'
      if ecs_compatibility?
        should include("rails" => hash_including("request" => hash_including("params" => params)))
      else
        should include("params" => params)
      end
    end
    # Completed
    it do
      if ecs_compatibility?
        should include("http" => hash_including("response" => { "status_code" => 200 }))
      else
        should include("response" => "200" )
      end
    end
    # in
    it do
      if ecs_compatibility?
        should include("rails" => hash_including("request" => hash_including("duration" => { "total" => 640.0, "view" => 1.7, "active_record" => 91.0 })))
      else
        should include("totalms" => "640", "viewms" => "1.7", "activerecordms" => "91.0")
      end
    end
  end
end
