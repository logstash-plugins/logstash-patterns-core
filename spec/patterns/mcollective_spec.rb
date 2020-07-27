# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe "MCOLLECTIVE" do

  let(:pattern) { "MCOLLECTIVE" }
  let(:value) { "I, [2010-12-29T11:15:32.321744 #11479]  INFO -- : mcollectived:33 The Marionette Collective 1.1.0 started logging at info level" }

  subject { grok_match(pattern, value) }

  it { should include("timestamp"=>"2010-12-29T11:15:32.321744") }
  it { should include("pid"=>"11479") }
  it { should include("event_level"=>"INFO") }

  # NOTE: pattern seems unfinished - missing match of remaining message
  it 'should have extracted message' do
    # but did not :
    expect( subject['message'] ).to eql value
  end

end
