## 4.3.4
  - Fix: typo in CISCOFW302013_302014_302015_302016 grok pattern [#313](https://github.com/logstash-plugins/logstash-patterns-core/pull/313)

## 4.3.3

- Fix: parsing x-edge-location in CLOUDFRONT_ACCESS_LOG (ECS mode) [#311](https://github.com/logstash-plugins/logstash-patterns-core/pull/311)

## 4.3.2

- Fix: typo in BIN9_QUERYLOG pattern (in ECS mode) [#307](https://github.com/logstash-plugins/logstash-patterns-core/pull/307)

## 4.3.1

- Fix: incorrect syslog (priority) field name [#303](https://github.com/logstash-plugins/logstash-patterns-core/pull/303)
- Fix: missed `ciscotag` field ECS-ification (`cisco.asa.tag`) for the `CISCO_TAGGED_SYSLOG` pattern 

## 4.3.0

With **4.3.0** we're introducing a new set of pattern definitions compliant with Elastic Common Schema (ECS), on numerous 
places patterns are capturing names prescribed by the schema or use custom namespaces that do not conflict with ECS ones.

Changes are backwards compatible as much as possible and also include improvements to some of the existing patterns.

Besides fields having new names, values for numeric (integer or floating point) types are usually converted to their 
numeric representation to ease further event processing (e.g. `http.response.status_code` is now stored as an integer).

NOTE: to leverage the new ECS pattern set in Logstash a grok filter upgrade to version >= 4.4.0 is required.

- **aws**
  * in ECS mode we dropped the (incomplete) attempt to capture `rawrequest` from `S3_REQUEST_LINE`
  * `S3_ACCESS_LOG` will handle up-to-date S3 access-log formats (6 'new' field captures at the end)
    Host Id -> Signature Version -> Cipher Suite -> Authentication Type -> Host Header -> TLS version
  * `ELB_ACCESS_LOG` will handle optional (`-`) in legacy mode
  * null values such as `-` or `-1` time values (e.g. `ELB_ACCESS_LOG`'s `request_processing_time`)
    are not captured in ECS mode

- **bacula**
  - Fix: improve matching of `BACULA_HOST` as `HOSTNAME`
  - Fix: legacy `BACULA_` patterns to handle (optional) spaces
  - Fix: handle `BACULA_LOG` 'Job Id: X' prefix as optional
  - Fix: legacy matching of BACULA fatal error lines

- **bind**
  - `BIND9`'s legacy `querytype` was further split into multiple fields as:
     `dns.question.type` and `bind.log.question.flags`
  - `BIND9` patterns (legacy as well) were adjusted to handle Bind9 >= 9.11 compatibility
  - `BIND9_QUERYLOGBASE` was introduced for potential re-use

- **bro**
  * `BRO_` patterns are stricter in ECS mode - won't mistakenly match newer BRO/Zeek formats
  * place holders such as `(empty)` tags and `-` null values won't be captured
  * each `BRO_` pattern has a newer `ZEEK_` variant that supports latest Zeek 3.x versions
    e.g. `ZEEK_HTTP` as a replacement for `BRO_HTTP` (in ECS mode only),
    there's a new file **zeek** where all of the `ZEEK_XXX` pattern variants live

- **exim**
  * introduced `EXIM` (`EXIM_MESSAGE_ARRIVAL`) to match message arrival log lines - in ECS mode!

- **firewalls**
  * introduced `IPTABLES` pattern which is re-used within `SHOREWALL` and `SFW2`
  * `SHOREWALL` now supports IPv6 addresses (in ECS mode - due `IPTABLES` pattern)
  * `timestamp` fields will be captured for `SHOREWALL` and `SFW2` in legacy mode as well
  * `SHOREWALL` became less strict in containing the `kernel:` sub-string
  * `NETSCREENSESSIONLOG` properly handles optional `session_id=... reason=...` suffix
  * `interval` and `xlate_type` (legacy) CISCO fields are not captured in ECS mode

- **core** (grok-patterns)
  * `SYSLOGFACILITY` type casts facility code and priority in ECS mode
  * `SYSLOGTIMESTAMP` will be captured (from `SYSLOGBASE`) as `timestamp`
  * Fix: e-mail address's local part to match according to RFC (#273)

- **haproxy**
  * several ECS-ified fields will be type-casted to integer in ECS mode e.g. *haproxy.bytes_read*
  * fields containing null value (`-`) are no longer captured
    (e.g. in legacy mode `captured_request_cookie` gets captured even if `"-"`)

- **httpd**
  * optional fields (e.g. `http.request.referrer` or `user_agent`) are only captured when not null (`-`)
  * `source.port` (`clientport` in legacy mode) is considered optional
  * dropped raw data (`rawrequest` legacy field) in ECS mode
  * Fix: HTTPD_ERRORLOG should match when module missing (#299)

- **java**
  * `JAVASTACKTRACEPART`'s matched line number will be converted to an integer
  * `CATALINALOG` matching was updated to handle Tomcat 7/8/9 logging format
  * `TOMCATLOG` handles the default Tomcat 7/8/9 logging format
  * old (custom) legacy TOMCAT format is handled by the added `TOMCATLEGACY_LOG`
  * `TOMCATLOG` and `TOMCAT_DATESTAMP` still match the legacy format, 
      however this might change at a later point - if you rely on the old format use `TOMCATLEGACY_` patterns

- **junos**
  * integer fields (e.g. `juniper.srx.elapsed_time`) are captured as integer values

- **linux-syslog**
  * `SYSLOG5424LINE` captures (overwrites) the `message` field instead of using a custom field name
  * regardless of the format used, in ECS mode, timestamps are always captured as `timestamp`
  * fields such as `log.syslog.facility.code` and `process.pid` are converted to integers

- **mcollective**
  * *mcollective-patterns* file was removed, it's all one *mcollective* in ECS mode
  * `MCOLLECTIVE`'s `process.pid` (`pid` previously) is not type-casted to an integer

- **nagios**
  * numeric fields such as `nagios.log.attempt` are converted to integer values in ECS mode

- **rails**
  * request duration times from `RAILS3` log will be converted to floating point values

- **squid**
  * `SQUID3`'s `duration` http.response `status_code` and `bytes` are type-casted to int
  * `SQUID3` pattern won't capture null ('-') `user.name` or `squid.response.content_type`
  * Fix: allow to parse SQUID log with status 0 (#298)
  * Fix: handle optional server address (#298)

## 4.2.0
  - Fix: Java stack trace's JAVAFILE to better match generated names
  - Fix: match Information/INFORMATION in LOGLEVEL [#274](https://github.com/logstash-plugins/logstash-patterns-core/pull/274)
  - Fix: NAGIOS TIMEPERIOD unknown (from/to) field matching [#275](https://github.com/logstash-plugins/logstash-patterns-core/pull/275)
  - Fix: HTTPD access log parse failure on missing response [#282](https://github.com/logstash-plugins/logstash-patterns-core/pull/282)
  - Fix: UNIXPATH to avoid DoS on long paths with unmatching chars [#292](https://github.com/logstash-plugins/logstash-patterns-core/pull/292)

    For longer paths, a non matching character towards the end of the path would cause the RegExp engine a long time to abort.
    With this change we're also explicit about not supporting relative paths (using the `PATH` pattern), these won't be properly matched.
 
  - Feat: allow UNIXPATH to match non-ascii chars [#291](https://github.com/logstash-plugins/logstash-patterns-core/pull/291)

## 4.1.2
  - Fix some documentation issues

## 4.1.0
  - Added SYSLOG5424LINE and test ipv4/ipv6/hostname as syslog5424_host rfc5424
  - Accordig to rcf5424 IP address should be accepted
  - HTTPDATE is used by patterns/aws
  - HTTPD (formerly APACHE) deserves its own pattern and test files. See #45
  - httpd: sync names between httpd20 and httpd24
  - Adding maven version to the list of default Grok patterns
  - Added Redis Monitor Log format
  - Remove extra space in ASA-6-106015 rule
  - fix COMMONAPACHELOG specs
  - Added SuSEfirewall2 pattern
  - switch USER to HTTPDUSER for "auth" field (match email addresses)
  - bind9 pattern
  - Pattern for squid3 native format
  - Parse Cisco ASA-5-304001
  - use underscores instead of hyphens in field names
  - fix timestamp expect
  - fix cs_protocol pattern name
  - fix cs_protocol and cs_uri_query names
  - added cloudfront spec test
  - add pattern for cloudfront access log
  - Java Patterns: JAVASTACKTRACEPART was duplicate

## 4.0.2
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 4.0.1
  - Republish all the gems under jruby.

## 4.0.0
  - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141

## 2.0.5
  - Specs fixes, see https://github.com/logstash-plugins/logstash-patterns-core/pull/137

## 2.0.4
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.3
  - New dependency requirements for logstash-core for the 5.0 release

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

## 0.4.0
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

## 0.3.0
 - Updated the AWS S3 patterns
 - Added patterns for rails 3
 - Added patterns for haproxy
 - Added patterns for bro http.log
 - Added shorewall patterns
## 0.2.0
 - Added patterns for S3 and ELB access logs amazon services
## 0.1.12
 - add some missing Cisco ASA firewall system log patterns
 - fix cisco firewall policy_id regex for policies with '-' in the name
## 0.1.11
 - Added Catalina and Tomcat patterns
 - Added German month names
