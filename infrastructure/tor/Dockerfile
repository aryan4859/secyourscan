FROM alpine:3.20
RUN apk add --no-cache tor && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
  CMD nc -z 127.0.0.1 9050 || exit 1
CMD ["tor", "-f", "/etc/tor/torrc"]
