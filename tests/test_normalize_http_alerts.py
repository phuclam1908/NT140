"""Synthetic fixture smoke test (does not use CTU-13 raw data)."""
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'src/evaluation/normalize_http_alerts.py'
SRC = '147.32.84.165'


def make_csv(path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, columns)
        w.writeheader()
        w.writerows(rows)


class NormalizeSmokeTest(unittest.TestCase):
    def test_overlapping_alerts_and_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            logs = repo / 'data/processed/scenario-01-neris/zeek'
            out = repo / 'reports/week2/quy/generated'
            logs.mkdir(parents=True)
            out.mkdir(parents=True)
            conn = [
                {'uid': 'A', 'id.orig_h': SRC, 'id.orig_p': 1234,
                 'id.resp_h': '203.0.113.10', 'id.resp_p': 888, 'proto': 'tcp', 'conn_state': 'SF'},
                {'uid': 'B', 'id.orig_h': SRC, 'id.orig_p': 1235,
                 'id.resp_h': '203.0.113.11', 'id.resp_p': 80, 'proto': 'tcp', 'conn_state': 'SF'},
            ]
            http = [
                {'ts': 1000.0, 'uid': 'A', 'host': 'x.example:888', 'uri': '/evil.exe',
                 'method': 'GET', 'status_code': 200, 'response_body_len': 128, 'resp_fuids': ['F1']},
                {'ts': 1010.0, 'uid': 'B', 'host': 'y.example', 'uri': '/sn.php?c=ACDF',
                 'method': 'GET', 'status_code': 200, 'response_body_len': 1},
            ]
            (logs / 'conn.log').write_text(''.join(json.dumps(x) + '\n' for x in conn))
            (logs / 'http.log').write_text(''.join(json.dumps(x) + '\n' for x in http))
            make_csv(out / 'nonstandard_http_port_alerts.csv',
                     ['src_ip', 'dst_ip', 'dst_port', 'proto', 'http_host', 'uri_path', 'http_request_count'],
                     [dict(src_ip=SRC, dst_ip='203.0.113.10', dst_port=888, proto='tcp',
                           http_host='x.example:888', uri_path='/evil.exe', http_request_count=1)])
            make_csv(out / 'web_behavior_alerts.csv',
                     ['src_ip', 'dst_ip', 'dst_port', 'proto', 'http_host', 'uri_path', 'request_count'],
                     [dict(src_ip=SRC, dst_ip='203.0.113.11', dst_port=80, proto='tcp',
                           http_host='y.example', uri_path='/sn.php', request_count=1)])
            make_csv(out / 'executable_ingress_events.csv',
                     ['zeek_uid', 'timestamp_utc', 'src_ip', 'dst_ip', 'dst_port', 'http_host', 'uri_path'],
                     [dict(zeek_uid='A', timestamp_utc='1970-01-01T00:16:40.000000+00:00',
                           src_ip=SRC, dst_ip='203.0.113.10', dst_port=888,
                           http_host='x.example:888', uri_path='/evil.exe')])
            evidence = repo / 'packet.csv'
            make_csv(evidence, ['zeek_uid', 'dst_ip', 'dst_port', 'uri_path', 'mz_hex_prefix',
                                'response_frame', 'tcp_stream', 'note'],
                     [dict(zeek_uid='A', dst_ip='203.0.113.10', dst_port=888,
                           uri_path='/evil.exe', mz_hex_prefix='4d5a9000',
                           response_frame=15, tcp_stream=3, note='synthetic')])
            result = subprocess.run([sys.executable, str(SCRIPT), '--repo', str(repo),
                                     '--mz-ledger', str(evidence)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with (out / 'http_transaction_alert_matrix.csv').open(newline='') as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            self.assertEqual((rows[0]['t1571'], rows[0]['t1071_001'], rows[0]['t1105']), ('1','0','1'))
            self.assertEqual(rows[0]['mz_packet_verified'], 'yes')
            self.assertEqual((rows[1]['t1571'], rows[1]['t1071_001'], rows[1]['t1105']), ('0','1','0'))
            with (out / 'http_alerts_long.csv').open(newline='') as f:
                long_rows = list(csv.DictReader(f))
            self.assertEqual(len(long_rows), 3)
            self.assertTrue(all(not r['ground_truth_label'] for r in rows))


if __name__ == '__main__':
    unittest.main()
