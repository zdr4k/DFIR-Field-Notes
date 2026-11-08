# Under the Bit

Field notes from DFIR labs and investigations. Each case is a full walkthrough turned into reusable defense: an investigation report, IOCs, hunting queries and detection rules mapped to MITRE ATT&CK.

Companion repo for the **Under the Bit** series on [The Big Rollback](https://medium.com/@kelvinzdk).

## How it is organized

| Directory | What lives there |
| :--- | :--- |
| [`cases/`](./cases/) | One folder per walkthrough. Report, timeline, IOCs, hunting queries and the detections born from that case. |
| [`detections/`](./detections/) | Consolidated detection library. Sigma (vendor neutral) and KQL (Sentinel / Defender XDR), plus use case docs. |
| [`playbooks/`](./playbooks/) | Investigation workflows extracted from cases, reusable on the next incident. |
| [`cheatsheets/`](./cheatsheets/) | Artifact locations, commands and query snippets I keep reaching for. |
| [`templates/`](./templates/) | Starting point for new cases and detections. |

## Case index

| # | Case | Platform | Category | Key techniques | Detections |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 09 | [TabFlow Pro](./cases/UTB-09_TabFlow-Pro_LetsDefend/) | LetsDefend | Endpoint / Browser | T1176, T1200 | 🚧 |

## Workflow

1. Solve the lab, take notes in `evidence_notes/`.
2. Write the report from `templates/case_report.md`.
3. Turn findings into hunting queries, then into detections (see [`detections/DDLC.md`](./detections/DDLC.md)).
4. Promote stable rules from the case folder to `detections/`.
5. Publish the post and link it back in the case index.

## Ground rules

* No live malware or raw evidence in this repo. Hashes, defanged IOCs and code excerpts only.
* Lab answers and flags stay out of the reports. The walkthrough explains the method, the platform keeps its challenge.
* Detections are marked by maturity: `experimental`, `test`, `stable`.

## License

Content under CC BY 4.0. Detection rules under MIT. See [LICENSE](./LICENSE).
