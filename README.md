# Crossfyre templates

The checks and signatures the Crossfyre toolchain's engines run, and the mappings
toolmark reads CVE leads with:

| Folder | What it holds |
|---|---|
| [`plessor/`](plessor/) | plessor's templates: exposures, misconfigurations, panels, default logins, vulnerabilities and CVEs, in a subset of the nuclei format. |
| [`toolmark/`](toolmark/) | toolmark's signatures: one file a product, naming it from headers, cookies, pages, paths, banners and certificates. |
| [`mappings/`](mappings/) | The other names the CVE data gives a product, and the version maps for products whose CVEs are filed under other numbering. |

Each release of the [toolchain](https://github.com/clickswave/crossfyre-toolchain)
compiles in a copy of these folders as they stand when it is built.

Licensed under the MIT License, in [LICENSE](LICENSE), apart from two files in
`mappings/`, `versions.yaml` and `netscaler-stamps.csv`, which are read in part from data
under the Apache License 2.0 and are under it, in
[mappings/LICENSE-APACHE](mappings/LICENSE-APACHE). Their sources are credited in
[mappings/README.md](mappings/README.md).
