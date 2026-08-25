# Evaluation

Every document in this repository was checked against the code, the rule file, and the captured evidence. This document records what disagreed, what was corrected, and what still needs confirmation.

Three sources of truth were used and they rank in this order. The **sample files** and the **screenshots** are what the running pipeline actually produced. The **rule file and the script** are what is deployed. The **documents** describe both. Where a document disagreed with code, the document was corrected. Where the code disagreed with the evidence, the evidence won and the code was corrected, because the evidence proves the pipeline worked at some point in a way the shipped code does not.

## What Was Checked

| Check                                  | Method                                                                              | Result                                                        |
|----------------------------------------|-------------------------------------------------------------------------------------|---------------------------------------------------------------|
| Script behaviour against evidence      | ran the filter over a representative flow set                                       | 1 defect that would break the pipeline, corrected             |
| Rule inventory                         | every rule ID, level, and description in the XML against both tables that list them | consistent, 24 rules, IDs 117001 to 117024                    |
| Confirmed rule lists                   | the README table against the table in the detection logic document                  | 2 different lists, reconciled                                 |
| Reported alert volumes                 | every figure quoted in any document                                                 | 2 incompatible figures, one retained with its window stated   |
| Decoder path                           | the architecture document against the sample alerts                                 | contradiction, corrected from evidence                        |
| Versions                               | every version string in documents and configs                                       | 1 contradiction, corrected                                    |
| Shell commands                         | every command that changes state                                                    | 2 that do not do what the surrounding text says, corrected    |
| Document completeness                  | every fenced block opened and closed                                                | 1 truncated document, completed                               |
| Environment specific values            | the whole repository                                                                | 5 values published, now placeholders                          |
| Rule overlap                           | every port list and every frequency rule compared against the others                | 1 mislabelled rule, 2 overlapping pairs, recorded not changed |
| Reported figures against the dashboard | every alert count in every document against the dashboard capture                   | 3 conflicting sets, all corrected from the screenshot         |
| Sample continuity                      | the three sample files compared flow by flow                                        | raw and normalized match, alerts come from a wider capture    |

## Finding 1: The Filter Would Have Dropped Every Alert

This is the one that matters. In the shipped script, a flow was discarded when either endpoint matched the internal prefix:

```python
if is_excluded(src) or is_excluded(dst):
```

`is_excluded` returned true for anything starting with `INTERNAL_PREFIX`, and the destination of every inbound flow is the collector itself, which is inside that prefix. So every scan arriving from the internet was filtered out before reaching Wazuh, and the pipeline would produce nothing but internal chatter, which is also filtered. The result is a working looking pipeline that emits zero alerts.

The evidence contradicts that outright. `samples/normalized/netflow_wazuh_sample.json` and `samples/alerts/wazuh_alert_sample.json` both contain flows whose destination is the collector, which the shipped script could not have produced. The version that generated the evidence was not the version in the repository.

The filter is now split in two, which is what the surrounding documentation always described:

```python
def should_skip(src, dst):
    if is_noise(src) or is_noise(dst):     # multicast, broadcast, loopback, link local
        return True
    return is_internal(src) and is_internal(dst)   # both ends internal
```

Verified against a three flow set: an external to internal RDP flow is kept, an internal to internal SSH flow is dropped, and a multicast flow is dropped. The kept record matches the documented sample byte for byte.

## Finding 2: Two Documents Disagreed About the Decoder

The architecture document showed a **custom decoder** in the pipeline diagram and in prose. The README showed the **built in JSON decoder**. Both describe the same manager.

The evidence settles it. Every alert in `samples/alerts/wazuh_alert_sample.json` carries `"decoder": {"name": "json"}`, and rule 117001 keys on `<decoded_as>json</decoded_as>`. The built in decoder is what fires and the custom decoder is inert.

This is not a labelling detail. Installing `netflow_decoder.xml` gives matching events the decoder name `netflow_json` instead, at which point `<decoded_as>json</decoded_as>` no longer matches and **every rule in this project stops firing**. The installation document previously instructed copying the decoder into place as a required step, which means following it exactly could have produced a silent total failure.

The decoder is now documented as optional, with that consequence stated, and the copy step was removed from the required sequence. The file is kept because it is a reasonable starting point for anyone who wants to customize decoding later and is willing to adjust rule 117001 with it.

## Finding 3: Two Different Lists of Confirmed Rules

The README bolded six rules as confirmed against real traffic. The detection logic document marked eleven, adding 117001, 117003, 117008, 117012, and 117021.

The dashboard capture gives a third list, and it is the one drawn from the data rather than from memory. The alerts by rule breakdown shows 117001, 117002, 117003, 117004, 117008, 117010, 117013, 117018, 117020, and 117021 firing, and the alert samples add 117015 and 117022.

That is twelve rules with evidence behind them. Two rules the detection logic document called confirmed, 117012 for SMB and 117014 for FTP, appear in neither the dashboard breakdown nor the samples, so they are not counted here. Two rules neither document claimed, 117002 and 117018, are clearly present.

The README now names the twelve and states that the remaining twelve have not been observed firing. Half the ruleset unfired is a normal result for one host over one day, and saying so is worth more than a claim of coverage that the dashboard would contradict on inspection.

## Finding 4: Three Incompatible Alert Totals, Settled by the Dashboard

Three documents reported three different results for the same deployment.

| Document          | Total           | Window          | High severity           |
|-------------------|-----------------|-----------------|-------------------------|
| README            | 1,916           | 24 hours        | 187 at level 7 or above |
| Detection logic   | 2,490           | roughly 5 hours | 982 at level 9 or above |
| Portfolio content | more than 4,400 | roughly 5 hours | 982 at level 9 or above |

They cannot all describe one deployment. Two of them claim a five hour window while quoting totals that differ by nearly a factor of two, and the 24 hour figure is the smallest of the three.

`screenshots/Dashboard_Overview.png` settles it. The dashboard is set to Last 24 hours and reports **4,472 firing events** across **10 threat categories**. Every document now carries those figures.

The same screenshot also settles a second disagreement. The README recorded the NetBIOS source as producing 29 hits, while the other two documents said roughly 2,400. The representational table on the dashboard shows 2,470 hits on port 137 and 114 on port 138 from that source, so the README figure was wrong by two orders of magnitude.

That number changes how the total should be read, which is why it is now stated alongside it. One noisy external source accounts for well over half of all firing events, so 4,472 measures the volume of one talker more than it measures breadth of detection.

An earlier pass through this repository picked the README figures as authoritative on the grounds that they stated a window, and rewrote the other documents to match. That was wrong, and it propagated the least accurate set of numbers into the other two files before the dashboard capture was consulted. Screenshots outrank prose here, and they should have been read first.

## Finding 5: The Install Script Was the Wrong Version and the Wrong Tool

Two defects in the same section.

The install script was pinned to `4.7` while the technology stack table and every screenshot report `4.14`. Corrected to 4.14.

The agent install ran `wazuh-install.sh -a -t agent`. That script deploys the server components; it does not install agents, and `-t agent` is not one of its options. The agent step now uses the package repository with `WAZUH_MANAGER` and `WAZUH_AGENT_NAME` passed at install time, which is the supported path and also writes the manager address into `ossec.conf` without a follow up edit.

The follow up edit was itself broken:

```bash
sudo sed -i 's/MANAGER_IP/YOUR_MANAGER_IP/' /var/ossec/etc/ossec.conf
```

That replaces one placeholder with another placeholder, leaving the agent pointed at a name that does not resolve. It now targets the `<address>` element explicitly and substitutes a real value.

## Finding 6: The Configuration Document Was Truncated

`docs/CONFIGURATION.md` ended in the middle of a logrotate heredoc. The `EOF` terminator, the closing code fence, and everything after them were missing, so the last command in the document could not be copied and run, and any renderer would treat the rest of the file as code.

The block is completed, and two things that were missing from it are now stated. `copytruncate` is required because pmacctd and the script both hold their output files open. And rotation resets the raw log to line 1 while the script marker still holds the pre rotation count, which stalls processing until the log grows past that number, so the marker needs removing in `postrotate`.

## Finding 7: Two Documents Showed the Wrong Field Types

The README and the configuration document both presented the normalized log with quoted numeric values, as though the script emitted `"nf_dst_port": "3389"`. It does not, and neither does `samples/normalized/netflow_wazuh_sample.json`, which holds unquoted numbers.

The quoted form is what appears one stage later. The Wazuh JSON decoder converts every decoded value to a string before it fills the alert `data` block, which is why `samples/alerts/wazuh_alert_sample.json` shows `"nf_dst_port": "3389"` for the same flow. Both files were right; the two documents had copied the alert side representation into a section describing the normalized file.

The examples now show numbers, with a sentence explaining why the alert shows strings. The scripted field note in the detection logic document was also reworded: it previously implied the strings were the result of an earlier integer fix, when in fact the decoder stringifies regardless of what the script emits, so those scripted fields are required permanently rather than as a migration workaround.

Worth recording that an earlier pass through this repository got this backwards and changed the script to emit strings, on the strength of the two documents rather than the samples. The samples and the alert data together are the authority here, and they agree with each other.

## Finding 8: Environment Specific Values Were Published

The collector address, the internal subnet prefix, the capture interface name, the agent name, and the manager hostname appeared throughout the documents, configs, and samples. All five are now placeholders, listed in one table in the README.

The attacker addresses were deliberately kept. They belong to external scanning infrastructure rather than to this environment, and they are the only evidence that these rules fire on real traffic rather than on synthetic tests. Two of them were already partially masked in the original tables, `45.227.x.x` and `212.73.x.x`, which is an inconsistency that cannot be resolved upward, since the missing octets are not recoverable from what was published.

## Finding 9: Naming Conventions Were Mixed

File names used four conventions at once: lower case documents, spaces in screenshot names, a doubled extension in `ossec.conf.snippet`, and a `rules/rules/` path nested inside `rules/`.

Everything is now consistent. Documents are upper case with underscores, screenshots use underscores, the snippet files carry the `.xml` extension that matches their content, and the ruleset lives under `wazuh_ruleset/` with `decoders/` and `rules/` beneath it. One Indonesian word in a screenshot name, `Eksternal`, is now `External` in an otherwise English repository.

The compiled Python cache directory `scripts/__pycache__/` was also committed and is now removed, with `.gitignore` extended to keep it out.

## Finding 10: Nine Screenshots Were Never Referenced

Only the cover image was linked from any document. The other nine, including five `wazuh-logtest` captures showing individual rules matching a specific input, existed in the repository with no way to find them.

They are now listed in the README. The logtest captures carry more weight than the dashboard ones for a reader verifying the work, because they show a rule matching a named input rather than a count on a chart.

## Finding 11: The Documented Subnet Prefix Was Broader Than the One Deployed

The repository set `INTERNAL_PREFIX` to a prefix covering the whole `/16` style range the collector sits in. The dashboard shows alerts for flows between two addresses that both fall inside that range but in different `/24` blocks, on the C2 beaconing rule.

Under the corrected filter in finding 1, a flow is dropped when both endpoints are internal, so those alerts could not exist with the prefix as written. They can exist with a prefix scoped to the collector's own `/24`, which makes the other address external as far as the filter is concerned.

So the deployed prefix was narrower than the documented one. The value is now a placeholder, and the guidance is explicit that it should describe the subnet the collector sits in rather than a wider corporate range. A prefix set too broadly silently discards cross subnet traffic, which is the traffic most worth seeing in a segmented network, and it discards it without any counter that distinguishes it from ordinary noise.

## Finding 12: One Rule Does Not Do What Its Name Says

Rule `117018` is described as **High outbound traffic volume** and grouped under data exfiltration. Its condition is:

```xml
<rule id="117018" level="10" frequency="30" timeframe="60">
  <if_matched_sid>117001</if_matched_sid>
  <same_field>nf_src_ip</same_field>
```

It counts flows, not bytes. It has no reference to `nf_bytes`, and no condition establishing direction, so it fires on inbound scanning just as readily as on outbound transfer. A scanner hitting the host thirty times in a minute raises a level 10 data exfiltration alert.

It is also a strict subset of `117002`, which is **High connection volume from single source** at frequency 20 in the same 60 second window. Anything reaching 30 in 60 seconds has already reached 20, so 117018 never fires alone and always arrives as a duplicate at a higher level.

Two ways to make it mean what it says, and either needs a decision from whoever owns the tuning. Add a byte threshold on `nf_bytes` so it measures volume. Or add a direction condition so it only counts flows whose source is internal, which would need the internal prefix expressed as a rule level match rather than only in the script.

## Finding 13: Two Pairs of Rules Overlap

**Port 3333 is claimed twice.** `117003` lists it among suspicious ports at level 7, and `117017` lists it among cryptocurrency mining ports at level 9. A single flow to 3333 produces two alerts describing it two different ways. Pick one owner for the port.

**Beaconing and repeated connections are the same test.** `117004` fires on 10 flows to one destination in 120 seconds; `117021` fires on 10 flows to one destination in 300 seconds. Every match of the tighter window is also a match of the wider one, so 117021 adds a second alert at level 11 whenever 117004 fires at level 6.

Neither rule measures periodicity, which is what distinguishes beaconing from ordinary repeated traffic. Wazuh cannot express interval regularity in a frequency rule, so a genuine beaconing detection needs either a wider timeframe with a much lower frequency, or the analysis moved outside the rule engine.

Three rules also key on `same_field nf_src_ip` with no port filter and only different thresholds: `117002` at 20 in 60 seconds, `117009` at 15 in 30 seconds, and `117018` at 30 in 60 seconds. That is one measurement described three ways, and it accounts for a share of the alert volume that a reader would reasonably attribute to three distinct detections.

## What Was Not Changed

**Rule thresholds.** Several rules have frequency and timeframe values that suit a busier link than a single cloud VM. Tuning them without traffic to tune against would be guesswork.

**Rule 117003 port list.** It includes 8443 and 9090, which are common alternate HTTPS and admin ports and will produce false positives in most environments. Left as written, since it is a documented design choice rather than a defect, and noted here so the choice is visible.

**The cron schedule.** Alert latency is bounded by the cron interval plus the pmacctd flush interval, roughly two minutes. That is inherent to the design rather than an error, and it is now stated in the limitations rather than left for a reader to work out.

**The attacker addresses.** See finding 8.

**Rule 117018 and rule 117021.** See findings 12 and 13. Both are logic changes to detection content rather than corrections of a contradiction, and choosing new thresholds without traffic to measure against would be guesswork.
