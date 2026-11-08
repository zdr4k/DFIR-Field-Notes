# Detection Development Lifecycle

1. **Requirement:** a behavior observed in a case or a threat report.
2. **Research:** what telemetry records it, and how the OS or app generates that telemetry.
3. **Hunt:** write a broad query, run it, look at what comes back.
4. **Develop:** narrow into a rule. Write the Sigma first, then the native KQL.
5. **Test:** reproduce the behavior in a lab, confirm it fires. Run against benign baseline for noise.
6. **Document:** ADS use case in `use_cases/`.
7. **Promote:** `experimental` → `test` → `stable`, moving from the case folder to `detections/`.
8. **Review:** revisit when false positives show up or the technique evolves.
