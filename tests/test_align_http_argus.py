import csv
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src' / 'evaluation'))
import align_http_argus as a


def utc_ts(clock):
    return datetime.fromisoformat('2011-08-10T' + clock + '+00:00').timestamp()


class TestArgusAlignment(unittest.TestCase):
    def test_direct_overlap_and_other(self):
        key = ('147.32.84.165', 2275, '31.192.109.167', 80, 'tcp')
        nkey = ('147.32.84.165', 2345, '10.20.30.40', 80, 'tcp')
        c = {
            'uid1': {'key': key, 'start': utc_ts('10:12:54.127346'), 'end': utc_ts('10:12:54.286634')},
            'uid2': {'key': key, 'start': utc_ts('10:31:25.469770'), 'end': utc_ts('10:31:25.649460')},
            'uid3': {'key': nkey, 'start': utc_ts('10:44:44'), 'end': utc_ts('10:44:45')},
        }
        argus = [
            {'id': 2, 'key': key, 'start': utc_ts('10:12:54.604939'), 'end': utc_ts('10:31:26.227131'), 'start_raw': '2011/08/10 12:12:54.604939', 'label': 'flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted'},
            {'id': 3, 'key': nkey, 'start': utc_ts('10:44:44.5'), 'end': utc_ts('10:44:45.5'), 'start_raw': '2011/08/10 12:44:44.5', 'label': 'flow=From-Normal-V42-Example'},
        ]
        bykey = {key: [argus[0]], nkey: [argus[1]]}
        starts = {k: [r['start'] for r in v] for k,v in bykey.items()}
        result = a.classify_connections(c, bykey, starts, 2.0)
        self.assertEqual(result['uid1']['status'], 'direct_unique_start')
        self.assertEqual(result['uid2']['status'], 'overlap_association_only')
        self.assertEqual(result['uid3']['status'], 'direct_unique_start')
        self.assertEqual(a.policy_candidate(argus[0]['label']), 'dataset_positive_candidate')
        self.assertEqual(a.policy_candidate(argus[1]['label']), 'dataset_negative_candidate')
        self.assertEqual(a.policy_candidate('flow=Background-TCP-Established'), 'unlabeled_or_requires_policy_review')
        self.assertAlmostEqual(a.parse_prague('2011/08/10 12:12:54.604939'), argus[0]['start'], places=5)

    def test_repeated_claim_is_ambiguous(self):
        key = ('1.2.3.4', 100, '5.6.7.8', 80, 'tcp')
        f = {'id': 4, 'key': key, 'start': 1000.5, 'end': 1050, 'start_raw': 'dummy', 'label': 'flow=From-Botnet-Test'}
        conn = {'one': {'key': key, 'start': 1000.1, 'end': 1000.2},
                'two': {'key': key, 'start': 1000.3, 'end': 1000.4}}
        res = a.classify_connections(conn, {key: [f]}, {key: [f['start']]}, 2)
        self.assertEqual(res['one']['status'], 'ambiguous_multi_claim')
        self.assertEqual(res['two']['status'], 'ambiguous_multi_claim')


if __name__ == '__main__':
    unittest.main()
