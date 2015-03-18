FROM scratch
COPY . /
EXPOSE 8123
ENV CLOUDPROXY_TAO_HOST_CHANNEL_TYPE unix
ENV CLOUDPROXY_TAO_HOST_SPEC /tao
WORKDIR .
ENTRYPOINT ["/bin/demo_server", "--logtostderr", "--config", "/tao.config"]
