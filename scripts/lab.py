#!/usr/bin/env python3
"""Offline, standard-library reference validator for synthetic Splunk lab detections."""
import argparse
import csv
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'sample_data' / 'windows_events.jsonl'
RULES = ROOT / 'detections' / 'rules.json'

def load_events(path=DATA):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]

def load_rules(path=RULES):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def detect(events):
    """Reference behavior; SPL remains the source for execution in Splunk."""
    hits=[]
    groups=defaultdict(list)
    for e in events:
        if e.get('EventCode') == 4625 and e.get('user') not in ('-', 'ANONYMOUS LOGON'):
            # Synthetic events arranged in ten-minute buckets for a predictable lab.
            bucket=int(datetime.fromisoformat(e['_time'].replace('Z','+00:00')).timestamp())//600
            groups[(e.get('src_ip'),e.get('user'),bucket)].append(e)
        if e.get('EventCode')==4688 and ('-enc' in e.get('CommandLine','').lower() or '-encodedcommand' in e.get('CommandLine','').lower()):
            hits.append({'rule':'DET-002','host':e['host'],'user':e.get('user',''),'detail':'Encoded PowerShell command'})
        if e.get('EventCode')==7045 and e.get('ServiceName','').lower().startswith('lab-'):
            hits.append({'rule':'DET-003','host':e['host'],'user':e.get('user',''),'detail':'Lab-designated new service'})
        if e.get('EventCode')==4720:
            hits.append({'rule':'DET-004','host':e['host'],'user':e.get('TargetUserName',''),'detail':'New local/domain account created'})
    for (ip,user,_bucket), matching in groups.items():
        if len(matching)>=5:
            hits.append({'rule':'DET-001','host':matching[0]['host'],'user':user,'detail':f'{len(matching)} failed logons from {ip} in 10-minute bucket'})
    return sorted(hits,key=lambda h:(h['rule'],h['host'],h['user']))

def validate(events=None):
    events = load_events() if events is None else events
    rules=load_rules()
    expected={r['id'] for r in rules}
    if len(expected)!=len(rules): raise ValueError('Duplicate detection rule IDs')
    for e in events:
        for key in ('_time','host','EventCode','source','sourcetype'):
            if key not in e: raise ValueError(f'Missing event field: {key}')
        datetime.fromisoformat(e['_time'].replace('Z','+00:00'))
    hits=detect(events)
    if not {h['rule'] for h in hits}<=expected: raise ValueError('Unknown detection ID')
    return hits

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',default='',help='Write detected hits to a CSV path')
    args=p.parse_args()
    hits=validate()
    for hit in hits: print(f"{hit['rule']} | {hit['host']} | {hit['user']} | {hit['detail']}")
    print(f'Validated {len(load_events())} synthetic events, {len(load_rules())} rules, {len(hits)} alerts')
    if args.output:
        target=Path(args.output); target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=['rule','host','user','detail']);w.writeheader();w.writerows(hits)
        print('Wrote',target)
if __name__=='__main__': main()
