ARG ELASTIC_STACK_VERSION
ARG DISTRIBUTION_SUFFIX
FROM docker.elastic.co/logstash/logstash${DISTRIBUTION_SUFFIX}:${ELASTIC_STACK_VERSION}
# TODO push upstream - run setup.sh before bundle install
# install and enable password-less sudo for logstash user
# allows modifying the system inside the container e.g. using the .ci/setup.sh hook
USER root
RUN yum install -y sudo
RUN usermod -aG wheel logstash && \
    echo "logstash ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/logstash && \
    chmod 0440 /etc/sudoers.d/logstash
USER logstash
COPY --chown=logstash:logstash . /usr/share/plugins/plugin/
RUN cp /usr/share/logstash/logstash-core/versions-gem-copy.yml /usr/share/logstash/versions.yml
# NOTE: since 8.0 JDK is bundled as part of the LS distribution under $LS_HOME/jdk
ENV PATH="${PATH}:/usr/share/logstash/vendor/jruby/bin:/usr/share/logstash/jdk/bin"
ENV LOGSTASH_SOURCE="1"
ENV ELASTIC_STACK_VERSION=$ELASTIC_STACK_VERSION
# DISTRIBUTION="default" (by default) or "oss"
ARG DISTRIBUTION
ENV DISTRIBUTION=$DISTRIBUTION
# INTEGRATION="true" while integration testing (false-y by default)
ARG INTEGRATION
ENV INTEGRATION=$INTEGRATION
WORKDIR /usr/share/plugins/plugin
RUN .ci/setup.sh
RUN gem install bundler -v '< 2'
RUN bundle install --with test ci
RUN bundle exec rake vendor
