"""
Command-line interface for the Cyber Defense SOC Lab.

    python -m soclab serve                 # launch the tactical dashboard
    python -m soclab simulate --all        # fire every attack scenario (headless)
    python -m soclab simulate --scenario spray
    python -m soclab forensics --report reports/case.md
    python -m soclab rules                  # print the detection catalogue
    python -m soclab export-wazuh           # regenerate the Wazuh rules XML
"""

from __future__ import annotations

import argparse
import os
import sys

from .detection_engine import ingest
from .scenarios import SCENARIO_ORDER, get_scenario, all_scenarios
from .rules import all_rules
from .forensics import write_forensic_report, forensic_report
from . import log_generator as gen


def _c(text, code):  # tiny ANSI colouriser
    return f"\033[{code}m{text}\033[0m"


def cmd_serve(args):
    from .server import run
    run(host=args.host, port=args.port, baseline=not args.no_baseline)


def cmd_simulate(args):
    # seed a little baseline first so reports look realistic
    for ev in gen.baseline_batch(n=20):
        ingest(ev)

    keys = SCENARIO_ORDER if args.all else [args.scenario]
    total_alerts = 0
    for key in keys:
        if key not in SCENARIO_ORDER:
            print(_c(f"[!] unknown scenario '{key}'. options: "
                     f"{', '.join(SCENARIO_ORDER)}", "31"))
            sys.exit(1)
        sc = get_scenario(key)
        raised = []
        for ev in sc["events"]:
            raised.extend(ingest(ev))
        total_alerts += len(raised)
        print(_c(f"\n▶ SCENARIO: {sc['name']}", "1;36"))
        print(f"  objective : {sc['objective']}")
        print(f"  MITRE     : {', '.join(sc['mitre'])}")
        print(f"  events    : {len(sc['events'])} telemetry records emitted")
        if raised:
            for a in raised:
                colour = {"critical": "1;31", "high": "31",
                          "medium": "33", "low": "32"}.get(a["severity"], "0")
                print("  " + _c(f"⚑ {a['severity'].upper():8} "
                                f"{a['rule_id']} {a['summary']}", colour))
        else:
            print(_c("  (no alert raised — check thresholds)", "33"))
    print(_c(f"\n[✔] simulation complete — {total_alerts} alert(s) raised. "
             f"Data written to ./data/", "1;32"))


def cmd_forensics(args):
    # make sure there's something to report on
    if args.simulate_first:
        for ev in gen.baseline_batch(n=20):
            ingest(ev)
        for key in SCENARIO_ORDER:
            for ev in get_scenario(key)["events"]:
                ingest(ev)
    if args.report:
        path = write_forensic_report(args.report, analyst=args.analyst)
        print(_c(f"[✔] forensic report written to {path}", "1;32"))
    else:
        print(forensic_report(analyst=args.analyst))


def cmd_rules(args):
    print(_c("\n  CYBER DEFENSE SOC LAB — DETECTION CATALOGUE\n", "1;36"))
    for r in all_rules():
        colour = {"critical": "1;31", "high": "31",
                  "medium": "33", "low": "32", "info": "37"}.get(r.severity, "0")
        print(_c(f"  {r.id}  {r.name}", "1"))
        print("    severity : " + _c(r.severity.upper(), colour))
        print(f"    MITRE    : {', '.join(r.mitre_techniques)}")
        print(f"    logic    : {r.detection_logic}")
        print(f"    threshold: {r.threshold} in {r.window_seconds}s "
              f"| wazuh id {r.wazuh_rule_id}\n")


def cmd_export_wazuh(args):
    from .wazuh_export import write_wazuh_rules
    path = write_wazuh_rules(args.out)
    print(_c(f"[✔] Wazuh rules written to {path}", "1;32"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soclab",
        description="Cyber Defense SOC Lab — tactical SOC simulation toolkit.")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("serve", help="launch the tactical dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8000)
    sp.add_argument("--no-baseline", action="store_true",
                    help="disable background benign traffic")
    sp.set_defaults(func=cmd_serve)

    ss = sub.add_parser("simulate", help="run attack scenarios headlessly")
    g = ss.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true", help="run every scenario")
    g.add_argument("--scenario", choices=SCENARIO_ORDER, help="run one scenario")
    ss.set_defaults(func=cmd_simulate)

    sf = sub.add_parser("forensics", help="generate a forensic report")
    sf.add_argument("--report", help="output Markdown path (else print to stdout)")
    sf.add_argument("--analyst", default="SOC Analyst")
    sf.add_argument("--simulate-first", action="store_true",
                    help="run all scenarios before reporting")
    sf.set_defaults(func=cmd_forensics)

    sr = sub.add_parser("rules", help="print the detection rule catalogue")
    sr.set_defaults(func=cmd_rules)

    se = sub.add_parser("export-wazuh", help="regenerate the Wazuh rules XML")
    se.add_argument("--out", default="config/wazuh/local_rules.xml")
    se.set_defaults(func=cmd_export_wazuh)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
