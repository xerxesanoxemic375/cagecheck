FROM golang:1.26-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /cagecheck ./cmd/cagecheck

FROM scratch
COPY --from=builder /cagecheck /cagecheck
ENTRYPOINT ["/cagecheck"]
