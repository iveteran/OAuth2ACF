FROM golang:1.26.4-alpine AS build

RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.Version=compose" -o /oauth2acf .

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 oauth2acf \
    && mkdir -p /data \
    && chown oauth2acf:oauth2acf /data \
    && chmod 700 /data

COPY --from=build /oauth2acf /usr/local/bin/oauth2acf

USER oauth2acf
ENV OAUTH2ACF_LISTEN_ADDRESS=0.0.0.0:9090 \
    OAUTH2ACF_DATABASE_PATH=/data/oauth2.db
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:9090/readyz || exit 1
ENTRYPOINT ["oauth2acf"]
