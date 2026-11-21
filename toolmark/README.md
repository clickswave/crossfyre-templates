# toolmark signatures

One file a product. toolmark reads each host's landing page, and at the standard tier the
paths and scripts a signature asks for, and names each product whose evidence holds,
with its version when it can read one.

```yaml
id: apache-httpd                  # the file's name, lower case letters, digits and hyphens
info:
  name: Apache HTTP Server
  category: Web Server
  metadata:                       # its CPE, which CVE leads are looked up by
    vendor: apache
    product: http_server          # or a list, for a product the CPE dictionary splits
    part: a                       # a (the default) for an application, o for an OS
detect:
  any:
    - header: { name: server, regex: '(?i)apache' }
version:
  - header: { name: server, regex: '(?i)apache/([0-9.]+)' }
```

`detect` is a leaf or a group of them: `all`, `any`, and `none`, which holds when none of
its children does. `version` lists leaves whose pattern captures the version in a group,
the first that reads one giving it; a leaf there may give `since` and `until` instead,
where the version lies when its evidence is present. `distro` lists leaves that read the
tag of the distribution that built it. `implies` names what a product brings with it, and
`refines` the signature it is a more exact form of.

The leaves:

| Leaf | What it reads |
|---|---|
| `header` | a header's value, by `name` |
| `cookie` | a cookie the page sets, by a `name` pattern, and its value when there is a `regex` |
| `meta` | a meta tag's content, by `name` |
| `html` | the landing page's body |
| `script_src` | the `src` of each script the page loads |
| `path` | what the host answers for `path`: a `regex` over it, a `sha256` of the file, or none when its being there is the evidence. A version leaf can give `stamp`, a table in `mappings/` the time in a gzip file's header is looked up in |
| `script` | the first script the page loads whose `src` matches `src` |
| `not_found` | the page the host answers for a path it does not have |
| `banner` | what a service probe read from a service, by `name` (ssh, ftp, smtp...) |
| `tls` | the certificate's `subject` or `issuer`, by `name` |
| `rendered` | the landing page as a browser built it, at the rendered tier |

`path`, `script` and `not_found` cost a request and are read from the standard tier up.
A detect leaf can set `confidence`, between 1 and 100.
