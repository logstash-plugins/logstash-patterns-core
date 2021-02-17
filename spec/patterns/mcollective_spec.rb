# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "MCOLLECTIVE", ['legacy', 'ecs-v1'] do

  let(:message) { "I, [2010-12-29T11:15:32.321744 #11479]  INFO -- : mcollectived:33 The Marionette Collective 1.1.0 started logging at info level" }

  it do
    should include("timestamp" => "2010-12-29T11:15:32.321744")
  end

  it do
    if ecs_compatibility?
      should include("process" => { "pid" => 11479 })
    else
      should include("pid" => "11479")
    end
  end

  it do
    if ecs_compatibility?
      should include("log" => hash_including("level" => "INFO"))
    else
      should include("event_level" => "INFO")
    end
  end

  # NOTE: pattern seems unfinished - missing match of remaining message
  it 'should have extracted message' do
    # but did not :
    expect( subject['message'] ).to eql message
  end

end
