import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import lab

class DetectionTests(unittest.TestCase):
    def test_expected_hits(self):
        hits=lab.validate()
        self.assertEqual({h['rule'] for h in hits},{'DET-001','DET-002','DET-003','DET-004'})
        self.assertEqual(len(hits),4)
    def test_noise_does_not_trigger(self):
        events=[e for e in lab.load_events() if e['EventCode']==4624]
        self.assertEqual(lab.detect(events),[])
    def test_below_threshold(self):
        events=[e for e in lab.load_events() if e['EventCode']==4625 and e['host']=='LAB-WS02']
        self.assertEqual(lab.detect(events),[])
    def test_missing_field_rejected(self):
        with self.assertRaises(ValueError): lab.validate([{'EventCode':4625}])
    def test_rules_technique_ids(self):
        self.assertTrue(all(r['attack'].startswith('T') for r in lab.load_rules()))
    def test_sample_is_private_test_ranges(self):
        for e in lab.load_events():
            self.assertTrue(e['host'].startswith('LAB-'))
            if 'src_ip' in e:self.assertTrue(e['src_ip'].startswith('192.0.2.'))
if __name__=='__main__':unittest.main()
