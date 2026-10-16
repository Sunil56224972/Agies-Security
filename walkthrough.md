# Walkthrough

A ten-minute tour of the console, using the demo dataset. Start a throwaway demo server with `AEGIS_DEMO=1 AEGIS_DATA_FILE=.data/demo.json npm start` and create the administrator when prompted. Settings > Integrations > Reset sample data brings the dataset back at any point.

1. **Overview.** Six alerts are waiting, and the triage queue sorts them by severity, so Log4Shell (ALERT-2026-9001) is at the top. The Active rules tile shows how many rules your firewall has actually picked up, not just how many exist. Click "Investigate next".
2. **Investigation.** Follow the phase tracker:
   - The payload is classified as JNDI injection.
   - The target's inventory shows log4j-core 2.14.1, which falls inside the NVD CPE range for CVE-2021-44228. The CVE is also on CISA's KEV list.
   - Its logs show the exploit request returning 200, a JNDI lookup to the attacker, and Java spawning a shell that pulls a second stage.
   - Verdict: compromise confirmed. A BLOCK rule for the source and an ISOLATE rule for the host are published. In the default feed mode they stay `Pending` until a firewall pulls the feed, and the alert stays *confirmed*, not *contained*, until then.
   - Expand any step to see the exact tool arguments and results.
3. **False positive.** Open ALERT-2026-9003 and run it. The payload is the same, but the target runs FastAPI, has no Java and no matching CVE, and the request was rejected with a 401. The engine marks it a false positive and does not block anything.
4. **Override.** On any finished case, choose a different outcome and give a reason. Overriding a confirmed compromise to a false positive removes the rules that case created. Overriding the other way creates them. Both actions are recorded in the audit log under your name.
5. **Enforcement.** Under Settings > API keys, create a key with the `feed` scope and copy the feed command it shows. Run it: the response is the blocklist, one IP per line. Back on Containment, the rules that were `Pending` are now `Enforced`, and the detail says which key pulled them. Verify enforcement on `185.220.101.45` reads the same state back.
6. **Ingest.** Create a key with the `ingest` scope and post a Suricata EVE line with the command from the key dialog. The alert appears in the queue, attributed to the sensor that sent it. Sending it a second time is reported as a duplicate.
7. **Assets.** Import a CSV of hosts, or add a CVE by id from NVD. The exposure tags recompute from installed versions.
8. **Team.** Add a read-only user, then sign in as them in a private window: every write action is gone, and the API refuses writes too.

Press `/` at any point to search alerts, hosts, CVEs and rules.