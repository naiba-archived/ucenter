FROM golang:alpine AS binarybuilder
# Install build deps
RUN apk --no-cache --no-progress add --virtual build-deps build-base git linux-pam-dev
WORKDIR /go/src/github.com/naiba/ucenter/
COPY . .
RUN cd cmd/web \
    && go build -ldflags="-s -w"

FROM alpine:latest
RUN echo http://dl-2.alpinelinux.org/alpine/edge/community/ >> /etc/apk/repositories \
  && apk --no-cache --no-progress add \
    git \
    tzdata
# Copy binary to container
WORKDIR /ucenter
COPY template ./template
COPY static ./static
COPY --from=binarybuilder /go/src/github.com/naiba/ucenter/cmd/web/web ./ucenter

# Configure Docker Container
VOLUME ["/ucenter/data"]
EXPOSE 8080
CMD ["/ucenter/ucenter"]