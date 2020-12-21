# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

describe_pattern "BACULA_LOG_MAX_CAPACITY", ['legacy', 'ecs-v1'] do

  let(:message) do
    'User defined maximum volume capacity 108,372,182,400 exceeded on device "FStorage" (/var/lib/bac/storage).'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "bacula"=>{"volume"=>{"bytes"=>"108,372,182,400", "device"=>"FStorage", "path"=>"/var/lib/bac/storage"}}
    else
      should include("device"=>"FStorage")
    end
  end

end

describe_pattern "BACULA_LOG_END_VOLUME", ['legacy', 'ecs-v1'] do

  let(:message) do
    'End of medium on Volume "TestShortZN0014" Bytes=5,228,777 Blocks=82 at 21-Dec-2016 12:30.'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "bacula"=>hash_including("volume"=>{"name"=>"TestShortZN0014", "bytes"=>"5,228,777", "blocks"=>"82"})
      # bacula.timestamp is 'duplicate' information when the full BACULA_LOGLINE is matched
      # we're keeping it as it includes year and might be slightly off the matched timestamp
      should include "bacula"=>hash_including("timestamp"=>"21-Dec-2016 12:30")
    else
      should include("volume"=>"TestShortZN0014")
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_NEW_VOLUME

  let(:message) do
    '09-Jan 19:54 bacula-host JobId 265896: Created new Volume "FullAuto-8812" in catalog.'
    # NOTE: we do not match full message log format that look like:
    # 'Created new Volume="FullAuto-8812", Pool="FullFile", MediaType="FullFile" in catalog.'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '09-Jan 19:54'
    if ecs_compatibility?
      should include "bacula"=>{"volume"=>{"name"=>"FullAuto-8812"}, "job"=>{"id"=>"265896"}}
      should include "host" => {"hostname"=>"bacula-host"}
    else
      should include("volume"=>"FullAuto-8812")
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_NEW_LABEL

  let(:message) do
    '25-Aug 10:50 bacula-sd JobId 24: Labeled new Volume "Vol-0018" on device "FileChgr1-Dev1" (/opt/bacula/disk).'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '25-Aug 10:50'
    if ecs_compatibility?
      should include "bacula"=>hash_including("volume"=>{"name"=>"Vol-0018", "device"=>"FileChgr1-Dev1", "path"=>"/opt/bacula/disk"})
      should include "bacula"=>hash_including("job"=>{"id"=>"24"})
      should include "host" => {"hostname"=>"bacula-sd"}
    else
      should include("volume"=>"Vol-0018", "device" => "FileChgr1-Dev1")
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_WROTE_LABEL

  let(:message) do
    '25-Aug 10:50 bacula-sd JobId 24: Wrote label to prelabeled Volume "Volume01" on device "Device01" (/dev/nst0)'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '25-Aug 10:50'
    if ecs_compatibility?
      should include "bacula"=>hash_including("volume"=>{"name"=>"Volume01", "device"=>"Device01", "path"=>"/dev/nst0"})
    else
      should include("jobid"=>"24")
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_NEW_MOUNT

  let(:message) do
    '24-Aug 01:54 crey-sd JobId 215534: New volume "DiffAuto-4861" mounted on device "vDrive-1" (/usr/local/bac/volumes) at 24-Aug-2015 01:54.'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '24-Aug 01:54'
    if ecs_compatibility?
      should include "bacula"=>hash_including("volume"=>{"name"=>"DiffAuto-4861", "device"=>"vDrive-1", "path"=>"/usr/local/bac/volumes"})
    else
      should include("device"=>"vDrive-1", "volume"=>"DiffAuto-4861", "hostname"=>"crey-sd", "jobid"=>"215534")
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_NOOPENDIR

  let(:message) do
    '24-Feb 16:36 starfury-fd JobId 3: Could not open directory "/root": ERR=Permission denied'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '24-Feb 16:36'
    if ecs_compatibility?
      should include "file"=>{"path"=>"/root"}
      should include "error"=>{"message"=>"Permission denied"}
    else
      should include("berror"=>"Permission denied")
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_NOSTAT

  let(:message) do
    '15-Dec 17:50 u22.com JobId 13:      Could not stat /var/lib/bacula/bacula.sql: ERR=No such file or directory'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "timestamp" => '15-Dec 17:50'
      should include "file"=>{"path"=>"/var/lib/bacula/bacula.sql"}
      should include "error"=>{"message"=>"No such file or directory"}
    else
      # NOTE: not matching due BACULA_HOST
      # should include "bts" => '15-Dec 17:50'
      # should include "berror"=>"No such file or directory"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_ALL_RECORDS_PRUNED

  let(:message) do
    '12-Apr 14:23 VU0EM005: All records pruned from Volume "06D125L3"; marking it "Purged"'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '12-Apr 14:23'
    if ecs_compatibility?
      should include "bacula"=>{"volume"=>{"name"=>"06D125L3"}},
                     "host"=>{"hostname"=>"VU0EM005"}
    else
      should include "hostname"=>"VU0EM005", "volume"=>"06D125L3"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_PRUNED_JOBS

  let(:message) do
    '29-Jan 04:16 lbu02-dir: Pruned 24 Jobs for client uni-horn from catalog.'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '29-Jan 04:16'
    if ecs_compatibility?
      should include "bacula"=>{"client"=>{"name"=>"uni-horn"}}, "host"=>{"hostname"=>"lbu02-dir"}
    else
      should include "hostname"=>"lbu02-dir", "client"=>"uni-horn"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_STARTJOB

  let(:message) do
    '06-Mar 20:00 srvbkp-dir JobId 1075: Start Backup JobId 1075, Job=srv1-bind.2018-03-06_20.00.01_05'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '06-Mar 20:00'
    if ecs_compatibility?
      should include "bacula"=>{"job"=>{"name"=>"srv1-bind.2018-03-06_20.00.01_05", "id"=>"1075"}}
    else
      should include "job"=>"srv1-bind.2018-03-06_20.00.01_05", "jobid"=>"1075"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_DIFF_FS

  let(:message) do
    '01-Feb 00:34 ohms-fd JobId 1662:      /var/spool/bareos is a different filesystem. Will not descend from /var into it.'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '01-Feb 00:34'
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_JOBEND

  let(:message) do
    '28-Aug 21:55 bacula-sd JobId 16: Job write elapsed time = 00:00:01, Transfer rate = 0  Bytes/second'
  end

  it 'matches' do
    should include (ecs_compatibility? ? "timestamp" : "bts") => '28-Aug 21:55'
    if ecs_compatibility?
      should include "bacula"=>{"job"=>{"elapsed_time"=>"00:00:01", "id"=>"16"}}
    else
      should include "jobid"=>"16", "elapsed" => "00:00:01"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_VOLUME_PREVWRITTEN

  let(:message) do
    '17-Jan-2003 16:45 home-sd: Volume test01 previously written, moving to end of data.'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "timestamp" => '17-Jan-2003 16:45'
      should include "bacula"=>{"volume"=>{"name"=>"test01"}}
    else
      # fails to match (due timestamp format)
    end
  end

end

describe_pattern "BACULA_LOG_READYAPPEND", ['legacy', 'ecs-v1'] do

  let(:message) do
    'Ready to append to end of Volume "F-0032" size=97835302'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "bacula"=>{"volume"=>{"name"=>"F-0032", "size"=>97835302}}
    else
      should include "volume"=>"F-0032"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_CLIENT_RBJ

  let(:message) do
    '01-Aug 13:30 toe-fd JobId 686: shell command: run ClientRunBeforeJob "/etc/bacula/cbe_hanfs.sh /mnt/baxter/fs1"'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "bacula"=>{"job"=>{"id"=>"686", "client_run_before_command"=>'/etc/bacula/cbe_hanfs.sh /mnt/baxter/fs1'}}
    else
      should include "jobid"=>"686", "runjob"=>"/etc/bacula/cbe_hanfs.sh /mnt/baxter/fs1"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_FATAL_CONN

  let(:message) do
    '11-Nov 13:28 bacula-dir JobId 11: Fatal error: bsock.c:133 Unable to connect to Client: dc0-fd on dc0.teamworld.com:9102. ERR=Connection refused'
  end

  it 'matches' do
    if ecs_compatibility?
      should include "client"=>{"address"=>"dc0.teamworld.com", "port"=>9102},
                     "bacula"=>hash_including("client"=>{"name"=>"dc0-fd"}),
                      "error"=>{"message"=>"Connection refused"}
    else
      should include "client"=>"dc0-fd", "berror"=>"Connection refused"
    end
  end

end

describe_pattern "BACULA_LOGLINE", ['legacy', 'ecs-v1'] do # BACULA_LOG_NO_AUTH

  let(:message) do
    '16-May 11:59 samy-dir JobId 0: Fatal error: Unable to authenticate with File daemon at "cardam.home.domain:9102". Possible causes:'
  end

  it 'matches' do
    if ecs_compatibility?
      # NOTE: due a grok bug port:int type-casting does not work :
      #should include "client"=>{"address"=>"cardam.home.domain", "port"=>9102}
      expect( subject['client'] ).to be_a Hash
      expect( subject['client']['address'] ).to eql 'cardam.home.domain'
      expect( subject['client']['port'].to_i ).to eql 9102
    else
      # does not match due client address:port
    end
  end

end
