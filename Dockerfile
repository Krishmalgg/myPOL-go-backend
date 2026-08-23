FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -trimpath -ldflags='-s -w' -o /out/realtime ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/realtime /realtime
EXPOSE 8080/tcp 8443/udp
ENTRYPOINT ["/realtime"]
