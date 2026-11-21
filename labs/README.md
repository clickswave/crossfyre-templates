# Labs

A CVE template can name a container where the product is vulnerable and one where it is
patched. Every push runs the template against both: it must find the vulnerable one and
must not find the patched one.

The template declares its lab in `info.metadata`:

```yaml
info:
  metadata:
    lab:
      port: 3000                # what the product listens on in its container, 80 if not given
      ready: /api/health        # a path that answers 200 once it is up; without it, any answer
      wait: 300                 # the seconds it has to come up, 120 if not given
      vulnerable: { image: metabase/metabase:v0.40.4 }
      patched: { image: metabase/metabase:v0.40.5 }
```

Each side is an `image` to pull, or a folder here to `build`, with `args` for its
Dockerfile:

```yaml
      vulnerable: { build: labs/httpd-root-granted, args: { version: 2.4.49 } }
      patched: { build: labs/httpd-root-granted, args: { version: 2.4.50 } }
```

Pin the images by release, and make the patched side the first release that fixed the
CVE where there is one, with the same configuration as the vulnerable side, so that what
differs between the two is the fix. A product whose vulnerable state needs a setting
changed gets a folder here that changes it, as `httpd-root-granted` grants access to the
whole filesystem the way the Apache traversal CVEs need.

To run them yourself you need Docker, PyYAML and plessor's daemon with a database:

```sh
plessor --port 4445 daemon &
python3 labs/run.py --plessor "$(command -v plessor)" --port 4445 [template id...]
python3 -m pytest labs    # the runner's own tests
```
