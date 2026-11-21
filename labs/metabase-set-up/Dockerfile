# Metabase with its setup finished, at the release the build argument names: the first
# admin account is made, so the setup token no longer makes one.
ARG version
FROM metabase/metabase:${version}
COPY set-up.sh /tmp/set-up.sh
RUN sh /tmp/set-up.sh && rm /tmp/set-up.sh
