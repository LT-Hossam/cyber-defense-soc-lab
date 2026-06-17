# Cyber Defense SOC Lab — developer shortcuts
.PHONY: help install simulate serve forensics rules wazuh test clean

help:
	@echo "Cyber Defense SOC Lab"
	@echo "  make install    install dependencies"
	@echo "  make simulate   run all five attack scenarios headlessly"
	@echo "  make serve      launch the tactical web console (port 8000)"
	@echo "  make forensics  generate a forensic report to reports/"
	@echo "  make rules      print the detection rule catalogue"
	@echo "  make wazuh      regenerate config/wazuh/local_rules.xml"
	@echo "  make test       run the pytest detection suite"
	@echo "  make clean      remove runtime data and caches"

install:
	pip install -r requirements.txt

simulate:
	python -m soclab simulate --all

serve:
	python -m soclab serve --host 127.0.0.1 --port 8000

forensics:
	python -m soclab forensics --report reports/sample-forensic-report.md --analyst "SOC Analyst — Tier 2" --simulate-first

rules:
	python -m soclab rules

wazuh:
	python -m soclab export-wazuh

test:
	python -m pytest -q

clean:
	rm -rf data/*.jsonl __pycache__ soclab/__pycache__ tests/__pycache__ .pytest_cache
