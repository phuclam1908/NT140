#!/usr/bin/env python3
"""Synthetic unit tests for the NT140 Week 2 executable response metadata rule."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

import sys
from pathlib import Path

DETECTION_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "detection"
)

sys.path.insert(0, str(DETECTION_DIR))

from executable_ingress_detector import run

from executable_ingress_detector import run


class ExecutableIngressDetectorTests(unittest.TestCase):
    def write_jsonl(self, path, objs):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w') as f:
            for obj in objs:
                f.write(json.dumps(obj) + '\n')

    def test_file_fuid_link_and_extension_only_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            logs = repo / 'data/processed/scenario-01-neris/zeek'
            self.write_jsonl(logs / 'conn.log', [
                {'uid':'U1','id.orig_h':'147.32.84.165', 'id.orig_p':1234, 'id.resp_h':'60.190.223.75', 'id.resp_p':2012, 'proto':'tcp', 'conn_state':'SF'},
                {'uid':'U2','id.orig_h':'147.32.84.165', 'id.orig_p':1235, 'id.resp_h':'60.190.223.75', 'id.resp_p':2012, 'proto':'tcp', 'conn_state':'SF'},
                {'uid':'U3','id.orig_h':'147.32.84.165', 'id.orig_p':1236, 'id.resp_h':'8.8.8.8', 'id.resp_p':80, 'proto':'tcp', 'conn_state':'SF'},
            ])
            self.write_jsonl(logs / 'http.log', [
                {'uid':'U1','ts':1312967198.707651, 'host':'test:2012', 'uri':'/kp.exe', 'method':'GET', 'status_code':200, 'response_body_len':55808, 'resp_mime_types':['application/x-dosexec'], 'resp_fuids':['F1']},
                {'uid':'U2','ts':1312971008.674689, 'host':'test:2012', 'uri':'/kp.exe', 'method':'GET', 'status_code':200, 'response_body_len':55808, 'resp_mime_types':[], 'resp_fuids':[]},
                {'uid':'U3','ts':1312971018.674689, 'host':'example', 'uri':'/index.html', 'method':'GET', 'status_code':200, 'response_body_len':100, 'resp_mime_types':['text/html']},
            ])
            self.write_jsonl(logs / 'files.log', [
                {'fuid':'F1','mime_type':'application/x-dosexec', 'seen_bytes':55808, 'total_bytes':55808, 'missing_bytes':0},
            ])
            events, summary = run(repo, '147.32.84.165')
            self.assertEqual(2, len(events))
            self.assertEqual(1, len(summary))
            self.assertEqual('zeek_pe_mime', events[0]['evidence_level'])
            self.assertEqual('uri_extension_only', events[1]['evidence_level'])
            self.assertEqual('F1', events[0]['files_log_matched_fuids'])
            self.assertEqual(111616, summary[0]['reported_response_body_bytes_sum'])
            self.assertEqual(1, summary[0]['pe_mime_transaction_count'])
            self.assertEqual('no', summary[0]['download_complete_verified'])
            with (repo / 'reports/week2/quy/generated/executable_ingress_candidates.csv').open() as f:
                self.assertEqual(1, len(list(csv.DictReader(f))))

    def test_no_files_log_and_no_body_or_failed_status_are_not_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            logs = repo / 'data/processed/scenario-01-neris/zeek'
            self.write_jsonl(logs / 'conn.log', [
                {'uid':str(n), 'id.orig_h':'147.32.84.165', 'id.resp_h':'1.1.1.1', 'id.resp_p':80, 'proto':'tcp'}
                for n in range(3)
            ])
            self.write_jsonl(logs / 'http.log', [
                {'uid':'0', 'ts':1, 'uri':'/ok.exe', 'status_code':200, 'response_body_len':2048, 'resp_mime_types':['application/x-dosexec']},
                {'uid':'1', 'ts':2, 'uri':'/bad.exe', 'status_code':404, 'response_body_len':2048, 'resp_mime_types':[]},
                {'uid':'2', 'ts':3, 'uri':'/empty.exe', 'status_code':200, 'response_body_len':0, 'resp_mime_types':[]},
            ])
            events, summary = run(repo, '147.32.84.165')
            self.assertEqual(1, len(events))
            self.assertEqual(1, len(summary))
            self.assertEqual('false', events[0]['files_log_available'])

if __name__ == '__main__':
    unittest.main()
