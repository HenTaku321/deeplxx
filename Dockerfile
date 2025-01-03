FROM golang:latest AS builder

WORKDIR /

COPY . .

RUN CGO_ENABLED=0 go build main.go

FROM alpine:latest

COPY --from=builder /main /main

EXPOSE 9000

CMD ["/main", "-c"]
