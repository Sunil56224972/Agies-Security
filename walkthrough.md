# Walkthrough

A five-minute tour of the console. It assumes a fresh sandbox; use Settings > Reset demo data to get one.

1. **Overview.** Six alerts are waiting. The triage queue sorts them by severity, so Log4Shell (ALERT-2026-9001) is at the top. Click "Work next alert".
2. **Investigation.** Press "Run investigation" and follow the phase tracker:
   - The payload is classified as JNDI injection.
   - The target turns out to be a Java app running log4j-core 2.14.1.
   - Its logs show the exploit request returning 200, a JNDI lookup to the attacker, and Java spawning a shell that pulls a second stage.
   - Verdict: compromise confirmed. The source is blocked, the host is isolated, and the probe confirms both.
   - Expand any step to see the exact tool arguments and results.
3. **False positive.** Open ALERT-2026-9003 and run it. The payload is the same, but the target runs FastAPI, has no Java and no matching CVE, and the request was rejected with a 401. The engine marks it a false positive and does not block anything.
4. **Override.** On any finished case, choose a different outcome and give a reason. Overriding a confirmed compromise to a false positive disables the rules that case created. Overriding the other way creates them. Both actions are recorded in the audit trail.
5. **Containment.** Every rule shows who created it and for which case. Probe `185.220.101.45` to see it reported as blocked; probe an unknown IP to see it reported as exposed, with a one-click block.
6. **Assets and telemetry.** Search the CVE knowledge base for `log4j`, or filter a host's logs by remote IP to see the raw lines the engine used.
7. **Settings.** Set the auto-containment policy and the confidence threshold, choose the engine, and check which storage backend is active.

Press `/` at any point to search everything.