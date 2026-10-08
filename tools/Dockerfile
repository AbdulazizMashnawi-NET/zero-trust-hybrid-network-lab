# One image, every role. Built locally by each team (needs Internet once).
FROM alpine:3.20

RUN apk add --no-cache \
        nftables iproute2 iptables \
        nmap nmap-scripts \
        tcpdump \
        openssl curl \
        python3 \
        wireguard-tools \
        openssh openssh-client \
        bind-tools \
        bash jq

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
