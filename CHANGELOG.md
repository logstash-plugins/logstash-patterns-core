## 4.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 4.0.1
  - Republish all the gems under jruby.
## 4.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
# 2.0.5
  - Specs fixes, see https://github.com/logstash-plugins/logstash-patterns-core/pull/137
# 2.0.4
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.3
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

# 0.4.0
 - Added grok patterns for nagios notifications
 - Added commong exim patterns
 - Allow optional space between sysloghost and colon, fixes https://github.com/elastic/logstash/issues/2101 for Cisco ASA devises.
 - Make progname optional (not always provided) for the syslog base patern.
 - Improve pattern matching performance for IPV4 patterns.
 - Fixes: UNIXPATH pattern does not combine well with comma delimination, https://github.com/logstash-plugins/logstash-patterns-core/issues/13
 - Add new valid characters for URI's in HTML5 patterns.
 - Make IPORHOST pattern match first an IP and then a HOST as the name
   implies.
 - Added patterns for ASA-4-106100, ASA-4-106102, ASA-4-106103 CISCO
   firewalls.
 - Update CISCOFW106023 rule to match values from FWSM
 - Add basic apache httpd error log format
 - Support TIMESTAMP_ISO8601 in HAProxy patterns, useful for rsyslog and other systems that can be configured to use this format. Fixes https://github.com/logstash-plugins/logstash-patterns-core/pull/80

# 0.3.0
 - Updated the AWS S3 patterns
 - Added patterns for rails 3
 - Added patterns for haproxy
 - Added patterns for bro http.log
 - Added shorewall patterns
# 0.2.0
 - Added patterns for S3 and ELB access logs amazon services
# 0.1.12
 - add some missing Cisco ASA firewall system log patterns
 - fix cisco firewall policy_id regex for policies with '-' in the name
# 0.1.11
 - Added Catalina and Tomcat patterns
 - Added German month names
