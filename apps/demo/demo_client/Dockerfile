FROM scratch
COPY . /home/tmroeder/src/github.com/jlmucb/cloudproxy/test
ADD tmp /tmp
ENV GOOGLE_HOST_TAO_TYPE unix
ENV GOOGLE_HOST_TAO /tao
WORKDIR /home/tmroeder/src/github.com/jlmucb/cloudproxy/test
ENTRYPOINT ["/home/tmroeder/src/github.com/jlmucb/cloudproxy/test/bin/demo_client"]
