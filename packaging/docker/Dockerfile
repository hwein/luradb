FROM ubuntu:24.04

# The .deb comes from the debdir build context (= target/debian, compose.yaml).
# Several may lie there (older builds) - install the most recently added one.
COPY --from=debdir luradb_*.deb /tmp/debs/
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl "$(ls -t /tmp/debs/luradb_*.deb | head -n1)" \
    && rm -rf /var/lib/apt/lists/* /tmp/debs

# Docker port mapping reaches the container via its network interface only;
# the host-side bind stays local (compose.yaml publishes 127.0.0.1 only).
# The grep asserts the patch landed - a drifted pattern is a silent no-op.
RUN sed -i 's/^bind_address = "127.0.0.1"$/bind_address = "0.0.0.0"/' /etc/luradb/luradb.toml \
    && grep -q '^bind_address = "0.0.0.0"$' /etc/luradb/luradb.toml
# Swagger UI on for local exploring; the package default (false) stays untouched.
RUN sed -i 's/^swagger_enabled = false$/swagger_enabled = true/' /etc/luradb/luradb.toml \
    && grep -q '^swagger_enabled = true$' /etc/luradb/luradb.toml
COPY entrypoint.sh /usr/local/bin/luradb-entrypoint
RUN chmod +x /usr/local/bin/luradb-entrypoint
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/luradb-entrypoint"]
