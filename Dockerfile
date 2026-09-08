FROM alpine:3.24

RUN apk add --no-cache \
    python3 \
    file \
    clamav \
    clamav-libunrar \
    bash \
    tzdata \
    lsof \
    su-exec \
    shadow

RUN mkdir -p /var/lib/clamav /app /state /quarantine

COPY scanner.py /app/scanner.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=5m --timeout=10s --start-period=2m \
  CMD pgrep -f "scanner.py watch" > /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
