# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "RAILS" do
  let(:rails3_pattern)  { "RAILS3" }

  context "Parsing RAILS3 single-line log from raw log file" do

    let(:value) { 'Started POST "/api/v3/internal/allowed" for 127.0.0.1 at 2015-08-05 11:37:01 +0200' } 

    subject     { grok_match(rails3_pattern, value) }

    # Started
    it { should include("verb" => "POST" ) }
    it { should include("request" => "/api/v3/internal/allowed" ) }
    # for
    it { should include("clientip" => "127.0.0.1" ) }
    # at
    it { should include("timestamp" => "2015-08-05 11:37:01 +0200" ) }
  end

  context "Parsing RAILS3 multi-line log from raw log file" do

    let(:value) { 'Started GET "/puppet/postfix/notes?target_id=162&target_type=issue&last_fetched_at=1438695732" for 127.0.0.1 at 2015-08-05 07:40:22 +0200
Processing by Projects::NotesController#index as JSON
  Parameters: {"target_id"=>"162", "target_type"=>"issue", "last_fetched_at"=>"1438695732", "namespace_id"=>"puppet", "project_id"=>"postfix"}
Completed 200 OK in 640ms (Views: 1.7ms | ActiveRecord: 91.0ms)' } 
    subject     { grok_match(rails3_pattern, value) }

    # started
    it { should include("verb" => "GET" ) }
    it { should include("request" => "/puppet/postfix/notes?target_id=162&target_type=issue&last_fetched_at=1438695732" ) }
    # for
    it { should include("clientip" => "127.0.0.1" ) }
    # at
    it { should include("timestamp" => "2015-08-05 07:40:22 +0200" ) }
    # Processing by
    it { should include("controller" => "Projects::NotesController" ) }
    it { should include("action" => "index" ) }
    # as
    it { should include("format" => "JSON" ) }
    # Parameters
    it { should include("params" => '"target_id"=>"162", "target_type"=>"issue", "last_fetched_at"=>"1438695732", "namespace_id"=>"puppet", "project_id"=>"postfix"' ) }
    # Completed
    it { should include("response" => "200" ) }
    # in
    it { should include("totalms" =>  "640" ) }
    # (Views: 
    it { should include("viewms" =>  "1.7" ) }
    # | ActiveRecord:
    it { should include("activerecordms" =>  "91.0" ) }

  end

end
