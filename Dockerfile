FROM golang:1.25.4-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend .

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o app ./cmd/server

FROM alpine:latest
WORKDIR /app
RUN apk --no-cache add ca-certificates sqlite-libs

RUN mkdir -p /app/data

COPY --from=builder /app/app .

EXPOSE 8080
CMD ["./app"]