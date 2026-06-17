# Elastic Stack configuration

These files describe how the Cyber Defense SOC Lab's telemetry is indexed, searched,
and visualised in a production deployment. In the lab itself, the tactical console
plays the role Kibana would here.

## Components
- **Elasticsearch** — stores normalised events shipped by Winlogbeat (Windows) and
  Filebeat (Linux). Indices: `winlogbeat-soclab-*`, `filebeat-soclab-*`.
- **Kibana** — search, dashboards, and the MITRE ATT&CK navigator overlay.

## Index lifecycle
For a lab, ILM is disabled (`setup.ilm.enabled: false`) so indices are simple and
predictable. In production, enable ILM with a hot/warm/delete policy sized to your
retention requirement (e.g. 90 days hot, 1 year warm).

## Recommended Kibana saved objects
Build these to mirror the tactical console's four dashboards:
1. **Security Overview** — event volume over time, severity breakdown, DEFCON gauge.
2. **Threat** — alert table with severity + MITRE technique columns.
3. **Incident** — open cases by phase.
4. **User Activity** — top accounts and source IPs by event count.

## Detection parity
Detection logic lives in Wazuh (`config/wazuh/local_rules.xml`) and the lab engine.
Elastic is the storage/visualisation layer; if you prefer Elastic detection rules,
the same eight SOC-00X logics translate directly to EQL/KQL detection rules.
