# Test plan

1. Run `python scripts/generate_data.py` and `python -m unittest discover -s tests -v`.
2. Run `python scripts/lab.py --output output/findings.csv`; expect exactly four findings, one per rule.
3. In Splunk, import the sample JSONL and verify `index=lab_windows | stats count by EventCode`.
4. Run each SPL block **separately** (the file is a collection, not one pasteable query).
5. Verify one failed-logon burst, one encoded command, one lab service installation, one account creation.
6. Review the three sub-threshold 4625 events and eight 4624 events; they should not generate findings.
7. Document and screenshot results from your own lab only after independently running the searches.

**Caution:** Offline Python reference validation is not equivalent to executing SPL in a running Splunk instance. SPL syntax and field extraction must be verified in your Splunk deployment.
