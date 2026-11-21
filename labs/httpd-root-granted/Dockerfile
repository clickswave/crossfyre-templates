# Apache HTTP Server with access to the whole filesystem granted, the configuration that
# CVE-2021-41773 and CVE-2021-42013 need, at the release the build argument names.
ARG version
FROM httpd:${version}
RUN sed -i '/^<Directory \/>/,/^<\/Directory>/ s/Require all denied/Require all granted/' conf/httpd.conf \
 && grep -A3 '^<Directory />' conf/httpd.conf | grep -q 'Require all granted'
