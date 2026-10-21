#!/usr/bin/env python3
"""Deterministically generate fictional events; no real host/user information."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'sample_data'/'windows_events.jsonl'
base={'source':'WinEventLog:Security','sourcetype':'WinEventLog:Security'}
events=[]
def add(time,host,code,**kwargs):
    events.append(dict(_time=f'2026-10-01T{time}Z',host=host,EventCode=code,**(base | kwargs)))
for i in range(6): add(f'10:01:{i*10:02d}','LAB-DC01',4625,user='lab.user',src_ip='192.0.2.55',LogonType=3)
for i in range(3): add(f'10:20:{i*10:02d}','LAB-WS02',4625,user='other.user',src_ip='192.0.2.60',LogonType=3)
add('10:30:00','LAB-WS01',4688,user='lab.admin',NewProcessName=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',CommandLine='powershell.exe -EncodedCommand RgBBAEsARQA=')
add('10:35:00','LAB-SRV01',7045,user='SYSTEM',ServiceName='LAB-TestService',source='WinEventLog:System',sourcetype='WinEventLog:System')
add('10:40:00','LAB-DC01',4720,user='lab.admin',TargetUserName='lab.temp')
for i in range(8): add(f'11:00:{i*5:02d}','LAB-WS03',4624,user='lab.user',src_ip='192.0.2.25',LogonType=3)
OUT.write_text(''.join(json.dumps(x)+'\n' for x in events),encoding='utf-8')
print(f'Generated {len(events)} synthetic events at {OUT}')
