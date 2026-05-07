FROM golang:bookworm AS build
WORKDIR /src
COPY . .
ENV GOFLAGS=-buildvcs=false
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN make build-coredns

FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive

# Full Bookworm + systemd + classic ifupdown + dhclient so DHCP works like a normal appliance CT.
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	dbus \
	ifupdown \
	iproute2 \
	isc-dhcp-client \
	libpam-systemd \
	systemd \
	systemd-sysv \
	&& rm -rf /var/lib/apt/lists/*

# systemd in Docker/podman builds: deterministic machine-id, avoid networkd conflicting with ifupdown
RUN dbus-uuidgen --ensure=/etc/machine-id \
	&& ln -sf /etc/machine-id /var/lib/dbus/machine-id \
	&& ln -sf /dev/null /etc/systemd/system/systemd-networkd.service \
	&& ln -sf /dev/null /etc/systemd/system/systemd-networkd.socket \
	&& ln -sf /dev/null /etc/systemd/system/systemd-resolved.service

COPY packaging/network.interfaces /etc/network/interfaces
COPY packaging/pve-dns-lockdown.service /etc/systemd/system/pve-dns-lockdown.service
RUN ln -sf /lib/systemd/system/networking.service \
	/etc/systemd/system/multi-user.target.wants/networking.service \
	&& ln -sf /etc/systemd/system/pve-dns-lockdown.service \
	/etc/systemd/system/multi-user.target.wants/pve-dns-lockdown.service

COPY --from=build /src/bin/pve-dns-lockdown /usr/local/bin/pve-dns-lockdown
COPY Corefile.example /etc/pve-dns-lockdown/Corefile
COPY docs /usr/share/doc/pve-dns-lockdown/

STOPSIGNAL SIGRTMIN+3
EXPOSE 53/tcp 53/udp 80/tcp
CMD ["/lib/systemd/systemd"]
