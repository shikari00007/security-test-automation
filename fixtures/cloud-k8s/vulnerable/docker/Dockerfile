FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.com/install.sh | sh
COPY app /app
CMD ["/app/run"]
