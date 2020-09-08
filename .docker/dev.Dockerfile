FROM golang:1.14-alpine AS builder

RUN apk -U --no-cache add build-base git gcc

WORKDIR /go/src/github.com/ory/kratos

ADD go.mod go.mod
ADD go.sum go.sum

RUN go mod download
RUN GO111MODULE=on go install github.com/gobuffalo/packr/v2/packr2 github.com/markbates/pkger/cmd/pkger

ADD . .

RUN packr2
RUN pkger
RUN CGO_ENABLED=1 go build -tags sqlite -a -o /usr/bin/kratos

FROM alpine:3.11

COPY --from=builder /usr/bin/kratos /usr/bin/kratos
# Add ca certificate(needed for oauth2 flow)
RUN apk add --no-cache ca-certificates && mkdir -p /usr/local/share/ca-certificates
COPY ./.docker/ca.crt /usr/local/share/ca-certificates/ca.crt
RUN update-ca-certificates

# Declare the standard ports used by Kratos (4433 for public service endpoint, 4434 for admin service endpoint)
EXPOSE 4433 4434

ENTRYPOINT ["kratos"]
CMD ["serve"]
