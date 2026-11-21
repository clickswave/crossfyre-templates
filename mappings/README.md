# Mappings

What toolmark reads alongside the CVE data to turn a product it found into CVE leads.

- `aliases.yaml`: the other names the CVE data gives a product a signature names by its
  CPE: a vendor's earlier name, the same product filed as firmware or software, or the
  package a library is published as. A product's leads are looked up under all of them.
- `versions.yaml`: for products whose CVEs are filed under other numbering than the
  version toolmark reads, what each version is asked for as. Exchange's builds become the
  cumulative updates NVD names, SharePoint's builds its releases, and the version of
  Erlang/OTP's ssh application the first OTP release that shipped it.
- `netscaler-stamps.csv`: each NetScaler build, by the time in the gzip header of
  `/vpn/js/rdx/core/lang/rdx_en.json.gz`. A time not in it gives no version.

## Licence and credits

`aliases.yaml` is under the repository's MIT License. `versions.yaml` and
`netscaler-stamps.csv` are read in part from the sources below that are under the Apache
License 2.0, and are under it too, in [LICENSE-APACHE](LICENSE-APACHE).

- Exchange Server's builds are read from Microsoft's "Exchange Server build numbers and
  release dates",
  https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates
- The versions of Erlang/OTP's ssh application in each OTP release are read from
  `otp_versions.table` in Erlang/OTP, https://github.com/erlang/otp. Copyright Ericsson AB.
  Licensed under the Apache License, Version 2.0. Changed: read into the first OTP release
  that shipped each ssh version.
- The NetScaler builds by stamp are read from the version table in
  `scan-citrix-netscaler-version.py` by Fox-IT,
  https://github.com/fox-it/citrix-netscaler-triage. Licensed under the Apache License,
  Version 2.0. Changed: the stamps whose build it does not know are left out.
