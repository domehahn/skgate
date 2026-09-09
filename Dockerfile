FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/skgate ./cmd/skgate

FROM scratch
COPY --from=build /out/skgate /skgate
USER 65532:65532
ENTRYPOINT ["/skgate"]
