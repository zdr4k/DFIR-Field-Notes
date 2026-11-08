# Detection library

Rules that started in a case and proved useful beyond it.

* `sigma/`: vendor neutral rules, convertible with `sigma convert`.
* `kql/`: native queries for Microsoft Sentinel and Defender XDR.
* `use_cases/`: one ADS document per detection.

Naming: `<technique>_<short_behavior>.<ext>`, for example `T1176_chrome_extension_sideload.yml`.

Lifecycle described in [DDLC.md](./DDLC.md).
