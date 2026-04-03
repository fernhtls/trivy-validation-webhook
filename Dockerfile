# Builder stage
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/main .

# Final stage
FROM alpine:latest
# Adding triby binary to alpine
RUN apk update
RUN apk add curl
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.69.3
# RUN apk add trivy
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
USER appuser
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 9000
CMD ["./main"]
