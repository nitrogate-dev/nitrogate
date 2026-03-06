FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /nitrogate ./cmd/nitrogate

FROM alpine:3.19
RUN apk add --no-cache ca-certificates git
COPY --from=builder /nitrogate /usr/local/bin/nitrogate
ENTRYPOINT ["nitrogate"]
