# Dashboard recipe (Splunk Search & Reporting)

Create a Classic dashboard manually in your own Splunk lab and add these panels:

**Events by type**
```spl
index=lab_windows | timechart span=10m count by EventCode
```

**Activity by host**
```spl
index=lab_windows | stats count by host EventCode | sort - count
```

**Failed authentication by source**
```spl
index=lab_windows EventCode=4625 | stats count by src_ip user | sort - count
```

**Lab process executions**
```spl
index=lab_windows EventCode=4688 | table _time host user NewProcessName CommandLine
```

Save screenshots of **your own verified lab results** in `docs/screenshots/` after deployment. No screenshots or dashboard exports are represented as already tested in Splunk.
