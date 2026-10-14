ARG GO_BUILD_IMAGE=golang:1.23-alpine
FROM ${GO_BUILD_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w -buildid=' -o /out/app ./cmd/server

FROM scratch
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/app /app/app
COPY schema.sql /app/schema.sql
EXPOSE 8080
ENV AUTH_SCHEMA_PATH=/app/schema.sql
ENV AUTH_DB_PATH=/data/auth.db
ENTRYPOINT ["/app/app"]
