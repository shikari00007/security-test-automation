FROM golang:1.22.5@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build
COPY . /src
RUN cd /src && go build -o /app

FROM gcr.io/distroless/static:nonroot
COPY --from=build /app /app
USER 65532:65532
CMD ["/app"]
