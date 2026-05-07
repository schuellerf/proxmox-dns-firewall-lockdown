FROM golang:bookworm AS build
WORKDIR /src
COPY . .
ENV GOFLAGS=-buildvcs=false
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN make build-coredns

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/bin/pve-lockdown /usr/local/bin/pve-lockdown
COPY Corefile.example /etc/pve-dns-lockdown/Corefile
COPY docs /usr/share/doc/pve-dns-lockdown/
EXPOSE 53/tcp 53/udp 80/tcp
CMD ["/usr/local/bin/pve-lockdown", "-conf", "/etc/pve-dns-lockdown/Corefile"]
