FROM golang:1.14.4 AS build

WORKDIR /go/src/app
COPY ./src .

RUN go get -d -v .
RUN go install -v .

FROM centos:7.7.1908

WORKDIR /opt

COPY --from=build /go/bin/app .

ENV PATH=$PATH:/opt
EXPOSE 3000
ENTRYPOINT ["app"]
