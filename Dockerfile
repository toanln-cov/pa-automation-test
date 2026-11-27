# stable build (supply chain, INFRA-18): base image pinned by digest + apt packages pinned by an Ubuntu snapshot time
# (snapshot.ubuntu.com) -> every build installs the same versions. Update = pull ubuntu:24.04, take the new digest and / or
# a new APT_SNAPSHOT (UTC, YYYYMMDDTHHMMSSZ), rebuild, retest
ARG BASE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
ARG APT_SNAPSHOT=20261126T155000Z

# stage 1: CA certificates only, so apt can reach https://snapshot.ubuntu.com (the base image has none; packages are
# still checked with the Ubuntu GPG key). Nothing else of this stage goes into the image
FROM ${BASE} AS certs
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

FROM ${BASE}
ARG APT_SNAPSHOT

ENV DEBIAN_FRONTEND=noninteractive

# Apache + mod_wsgi (built for the Python 3.12 of Ubuntu 24.04 LTS) + network tools to check the firewalls from the container:
# curl, dig/nslookup, traceroute, nc (no ping / tcpdump: they need NET_RAW, removed - INFRA-15). One layer, no recommended packages, apt lists removed (smaller image)
# every apt command reads the snapshot (APT::Snapshot); ca-certificates of the snapshot replaces the CA file of stage 1;
# upgrade = packages of the base image (libc6...) at their version of the snapshot, still the same on every build (INFRA-19)
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
# note: default-ssl site is NOT enabled (it needs the snakeoil cert of package ssl-cert);
# the HTTPS vhost of the tool is 000-default.conf with the per-installation cert in data/ssl/

# python packages in a virtualenv (PEP 668), no pip cache in the image;
# every package (incl. dependencies) pinned with sha256 hash -> install fails if a downloaded file was changed
COPY /www/automation_tool/django_app/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    # stable path for Django admin static files (served by Apache)
    && ln -s "$(/opt/venv/bin/python -c 'import django, os; print(os.path.join(os.path.dirname(django.__file__), "contrib/admin/static/admin"))')" /opt/admin-static

# apache config + application code (code is inside the image, only data/ and jobs/ are volumes)
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY apache/apache2.conf /etc/apache2/apache2.conf
COPY www/automation_tool /var/www/html
COPY entrypoint.sh /entrypoint.sh
# .pyc compiled at build time (root filesystem is read-only at run time);
# non-root Apache: listen on 8443 (no capability needed), data dirs owned by www-data
RUN chmod +x /entrypoint.sh \
    && /opt/venv/bin/python -m compileall -q /var/www/html \
    && printf 'Listen 8443\n' > /etc/apache2/ports.conf \
    && mkdir -p /var/www/html/data /var/www/html/jobs \
    && chown www-data:www-data /var/www/html/data /var/www/html/jobs \
    && chmod 700 /var/www/html/data /var/www/html/jobs

# container runs as www-data (uid 33), never root: limits what an attacker gets after an RCE (no root -> much harder escape)
USER www-data

#HTTPS port inside the container (docker-compose maps 9198 -> 8443)
EXPOSE 8443

# healthy = Apache + Django answer (any HTTP code < 500; 400 is fine when APP_ALLOWED_HOSTS does not list localhost)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/login/) && [ "$code" -ge 200 ] && [ "$code" -lt 500 ]

#first start: create data dirs, SSL cert, secret key, DB, default web user -> then start apache
CMD ["/entrypoint.sh"]
