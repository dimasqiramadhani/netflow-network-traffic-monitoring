# Installation

## Prerequisites

* Two virtual machines running Ubuntu 22.04 LTS (or a compatible Linux distribution).
* Network connectivity between both VMs.
* Root or sudo access on both VMs.
* Internet access for package installation.

## VM 1, Wazuh All in One Server

Install the Wazuh All in One deployment using the official quickstart method:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

This installs Wazuh Manager, Wazuh Indexer, and Wazuh Dashboard on a single VM. Note the admin credentials printed at the end of the installation.

Verify the services are running:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

## VM 2, Wazuh Agent

Install the Wazuh Agent on the second VM. The `wazuh-install.sh` script used above deploys
the server components and does not install agents, so use the repository instead and pass
the manager address through `WAZUH_MANAGER` at install time. That variable is written into
`ossec.conf` for you, which avoids editing the file afterwards.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="<MANAGER_IP>" WAZUH_AGENT_NAME="<AGENT_NAME>" apt install wazuh-agent -y
```

If the agent was installed without those variables, set the manager address by editing the
`<address>` element rather than by a blind substitution:

```bash
sudo sed -i 's|<address>MANAGER_IP</address>|<address><MANAGER_IP></address>|' /var/ossec/etc/ossec.conf
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verify the agent appears in the Wazuh Dashboard under **Agents**.

## VM 2, pmacctd

Install pmacctd from the pmacct package:

```bash
sudo apt update
sudo apt install pmacct -y
```

Create the log directory:

```bash
sudo mkdir -p /var/log/netflow
sudo chown root:root /var/log/netflow
```

Copy the pmacctd configuration:

```bash
sudo cp configs/pmacctd/pmacctd.conf /etc/pmacct/pmacctd.conf
```

Start pmacctd:

```bash
sudo pmacctd -f /etc/pmacct/pmacctd.conf -D
```

## VM 2, Python Normalization Script

Ensure Python 3 is installed:

```bash
python3 --version
```

Deploy the normalization script:

```bash
sudo mkdir -p /opt/netflow
sudo cp scripts/normalize_netflow_to_wazuh.py /opt/netflow/
sudo chmod +x /opt/netflow/normalize_netflow_to_wazuh.py
```

Test the script manually:

```bash
sudo python3 /opt/netflow/normalize_netflow_to_wazuh.py
```

Set up a cron job to run the script at regular intervals (e.g., every minute):

```bash
sudo crontab -e
# Add:
* * * * * /usr/bin/python3 /opt/netflow/normalize_netflow_to_wazuh.py
```

## VM 1, Rules

Copy the rules to the Wazuh Manager:

```bash
sudo cp wazuh_ruleset/rules/netflow_rules.xml /var/ossec/etc/rules/netflow_rules.xml
```

The decoder file is optional. Events are decoded by the built in JSON decoder, which is what
`<decoded_as>json</decoded_as>` in rule 117001 refers to. Installing
`wazuh_ruleset/decoders/netflow_decoder.xml` gives the events a different decoder name, and
rule 117001 then stops matching, so leave it out unless you also change that condition.

Restart the Wazuh Manager to load the new decoder and rules:

```bash
sudo systemctl restart wazuh-manager
```

Verify the decoder and rules are loaded without errors:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a sample normalized log line into logtest to confirm the decoder matches and rules fire.

## Verification

1. Confirm pmacctd is writing raw logs to `/var/log/netflow/netflow_raw.json`.
2. Confirm the Python script is producing normalized logs in `/var/log/netflow/netflow_wazuh.json`.
3. Confirm the Wazuh Agent is forwarding events (check `/var/ossec/logs/ossec.log` on VM 2).
4. Confirm alerts appear in the Wazuh Dashboard on VM 1.
