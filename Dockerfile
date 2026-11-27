# reproducible build: base pinned by digest, apt pinned to a snapshot.ubuntu.com time
# to update: new ubuntu:24.04 digest and/or APT_SNAPSHOT in UTC YYYYMMDDTHHMMSSZ, rebuild, retest
ARG BASE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
ARG APT_SNAPSHOT=20261126T155000Z

# CA certs only, so apt can reach the snapshot over https; packages still GPG checked
FROM ${BASE} AS certs
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

FROM ${BASE}
ARG APT_SNAPSHOT

ENV DEBIAN_FRONTEND=noninteractive

# no ping / tcpdump: they need NET_RAW
# upgrade moves base image packages to the snapshot version too
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN printf 'APT::Snapshot "%s";\n' "$APT_SNAPSHOT" > /etc/apt/apt.conf.d/50snapshot \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        apache2 libapache2-mod-wsgi-py3 python3 python3-venv openssl ca-certificates \
        curl dnsutils traceroute netcat-openbsd \
    && a2enmod ssl rewrite headers \
    && (a2disconf -q serve-cgi-bin other-vhosts-access-log || true) \
    && (a2dismod -q -f status autoindex cgi || true) \
    && rm -rf /var/lib/apt/lists/*
# default-ssl site not enabled, HTTPS is served by 000-default.conf

# hash-pinned deps: install fails if a downloaded file changed
COPY /www/automation_tool/django_app/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && ln -s "$(/opt/venv/bin/python -c 'import django, os; print(os.path.join(os.path.dirname(django.__file__), "contrib/admin/static/admin"))')" /opt/admin-static

COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY apache/apache2.conf /etc/apache2/apache2.conf
COPY www/automation_tool /var/www/html
COPY entrypoint.sh /entrypoint.sh
# precompile .pyc: rootfs is read-only at run time; 8443 needs no capability
RUN chmod +x /entrypoint.sh \
    && /opt/venv/bin/python -m compileall -q /var/www/html \
    && printf 'Listen 8443\n' > /etc/apache2/ports.conf \
    && mkdir -p /var/www/html/data /var/www/html/jobs \
    && chown www-data:www-data /var/www/html/data /var/www/html/jobs \
    && chmod 700 /var/www/html/data /var/www/html/jobs

# never root, limits what an RCE gets
USER www-data

EXPOSE 8443

# any code below 500 is healthy, 400 if APP_ALLOWED_HOSTS lacks localhost
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/login/) && [ "$code" -ge 200 ] && [ "$code" -lt 500 ]

CMD ["/entrypoint.sh"]
