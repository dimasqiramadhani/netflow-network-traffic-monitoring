# Troubleshooting

## pmacctd Not Capturing Traffic

**Symptom:** `/var/log/netflow/netflow_raw.json` is empty or not being created.

**Checks:**
1. Verify pmacctd is running: `ps aux | grep pmacctd`
2. Check the correct interface name in `/etc/pmacct/pmacctd.conf`: `ip link show`
3. Ensure the log directory exists and has correct permissions: `ls -la /var/log/netflow/`
4. Run pmacctd in foreground mode for debugging: `sudo pmacctd -f /etc/pmacct/pmacctd.conf` (remove `-D` flag)
5. Generate test traffic: `curl -s https://example.com > /dev/null` and check if raw logs appear.

## Python Script Not Producing Output

**Symptom:** `/var/log/netflow/netflow_wazuh.json` is empty or missing.

**Checks:**
1. Run the script manually: `sudo python3 /opt/netflow/normalize_netflow_to_wazuh.py`
2. Check for Python errors in the output.
3. Verify the raw input file exists and contains data: `cat /var/log/netflow/netflow_raw.json`
4. Check the cron job is configured: `sudo crontab -l`
5. Verify file permissions — the script needs read access to the raw file and write access to the output path.

## Wazuh Agent Not Forwarding Logs

**Symptom:** Events do not appear on the Wazuh Manager or Dashboard.

**Checks:**
1. Verify the agent is connected: check the Wazuh Dashboard under **Agents** or run `sudo /var/ossec/bin/wazuh-control status` on VM 2.
2. Check the agent log for errors: `sudo tail -50 /var/ossec/logs/ossec.log`
3. Confirm the `localfile` block is in `/var/ossec/etc/ossec.conf`:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/netflow/netflow_wazuh.json</location>
   </localfile>
   ```
4. Restart the agent after any config change: `sudo systemctl restart wazuh-agent`
5. Check that the Manager IP is correctly set in the agent's `ossec.conf`.

## Decoder Not Matching Events

**Symptom:** Events arrive at the Manager but are not decoded (they show as generic `syslog` or unmatched events in logtest).

**Checks:**
1. Run `wazuh-logtest` on VM 1: `sudo /var/ossec/bin/wazuh-logtest`
2. Paste a sample normalized JSON line and check the decoder output.
3. Verify the decoder file is in the correct path: `/var/ossec/etc/decoders/netflow_decoder.xml`
4. Check for XML syntax errors: `sudo /var/ossec/bin/wazuh-logtest` will report parsing errors on startup.
5. Restart the Manager after placing or modifying the decoder: `sudo systemctl restart wazuh-manager`

## Rules Not Triggering Alerts

**Symptom:** The decoder matches, but no alert appears in the Dashboard.

**Checks:**
1. In `wazuh-logtest`, confirm the rule ID fires after decoding.
2. Verify the rules file is in `/var/ossec/etc/rules/netflow_rules.xml`.
3. Check for XML errors in the rules file.
4. For frequency-based rules (117002, 117003, 117004), remember they require multiple events within the configured timeframe. A single test event will only trigger the base rule (117001).
5. Restart the Manager after any rule change.

## Alerts Not Appearing in the Dashboard

**Symptom:** `wazuh-logtest` shows alerts, but the Dashboard does not display them.

**Checks:**
1. Verify the Indexer is running: `sudo systemctl status wazuh-indexer`
2. Check if alerts are being written: `sudo tail -20 /var/ossec/logs/alerts/alerts.json`
3. Confirm the Dashboard can connect to the Indexer.
4. Check the Indexer disk space — if the disk is full, new alerts will not be indexed.
5. Wait a few minutes — there can be a short delay between alert generation and Dashboard visibility.

## General Tips

- Always restart services after configuration changes.
- Use `wazuh-logtest` as the primary debugging tool for decoder and rule issues.
- Check log files on both VMs (`/var/ossec/logs/ossec.log`) for error messages.
- If pmacctd raw logs look correct but normalized logs are wrong, check the Python script's field mapping logic.
- For network connectivity issues between VMs, verify firewall rules allow port 1514/TCP and 1515/TCP.
