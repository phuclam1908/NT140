"""Unit tests cho scripts/forensics_extract.py (chạy: pytest -q tests/test_forensics_extract.py)."""
import csv
import gzip
import importlib.util
import json
import os
import sys
from decimal import Decimal
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("forensics_extract", ROOT / "scripts" / "forensics_extract.py")
fx = importlib.util.module_from_spec(_spec)
sys.modules["forensics_extract"] = fx
_spec.loader.exec_module(fx)


# ------------------------------------------------------------------ hàm thuần
@pytest.mark.parametrize("value,expected", [
    ("1", True), ("0", False), ("True", True), ("False", False), ("true", True),
    ("", False), (None, False), ("0|1", True), ("False|False", False), (True, True),
])
def test_flag_on(value, expected):
    assert fx.flag_on(value) is expected


def test_iso_utc_microsecond_and_rounding():
    assert fx.iso_utc("1312967363.040703000") == "2011-08-10T09:09:23.040703Z"
    assert fx.iso_utc("1312966900.475792") == "2011-08-10T09:01:40.475792Z"
    # làm tròn half-even tới microsecond, không lỗi float
    assert fx.iso_utc("1312966900.4757925") == "2011-08-10T09:01:40.475792Z"
    assert fx.iso_utc("1312966900.9999996") == "2011-08-10T09:01:41.000000Z"
    assert fx.iso_utc("") == ""
    assert fx.iso_utc("abc") == ""


def test_rel6():
    assert fx.rel6("462.564911000") == "462.564911"
    assert fx.rel6("0") == "0.000000"
    assert fx.rel6("") == ""


def test_mask_email_and_token():
    assert fx.mask_email("FROM:<john.doe@example.com>") == "FROM:<j***@example.com>"
    assert fx.mask_email("no email here") == "no email here"
    assert fx.mask_token("HOSTNAME_0123456789ABCDE", 4) == "HOST...[len=24]"
    assert fx.mask_token("abc", 4) == "abc"


def test_mask_uri():
    assert fx.mask_uri("/sn.php?c=ABCDEF0123456789ABCDEF0123456789") == "/sn.php?c=ABCD...[len=32]"
    assert fx.mask_uri("/temp/3425.exe?t=0.3419458") == "/temp/3425.exe?t=0.3419458"
    assert fx.mask_uri("/?0123456789abcdef0123456789abcdef") == "/?0123...[len=32]"
    assert fx.mask_uri("/index.html") == "/index.html"


def test_redact_smtp_never_keeps_auth_payload():
    assert fx.redact_smtp("AUTH", "LOGIN") == "LOGIN"
    assert fx.redact_smtp("AUTH", "PLAIN dXNlcgB1c2VyAHBhc3M=") == "PLAIN [initial-response-redacted]"
    assert "dXNlcg" not in fx.redact_smtp("auth", "plain dXNlcgB1c2VyAHBhc3M=")
    assert fx.redact_smtp("MAIL", "FROM:<alice@example.org>") == "FROM:<a***@example.org>"
    assert fx.redact_smtp("RCPT", "TO:<bob@example.net>") == "TO:<b***@example.net>"
    assert fx.redact_smtp("EHLO", "someuser_name42") == "som...[len=15]"
    assert fx.redact_smtp_response("334", "VXNlcm5hbWU6") == "[auth-challenge-redacted]"
    assert fx.redact_smtp_response("250", "OK <carol@example.com>") == "OK <c***@example.com>"


def test_dup_detector_window():
    d = fx.DupDetector()
    k = ("T", "0x0001", "a", "b", "1", "2", "100", "0", "0x002")
    assert d.is_dup(k, Decimal("1.000000")) is False
    assert d.is_dup(k, Decimal("1.000010")) is True          # 10 µs -> trùng
    assert d.is_dup(k, Decimal("1.500000")) is False         # 0.5 s -> không coi là trùng
    assert d.is_dup(("T", "other"), Decimal("1.500001")) is False


# ----------------------------------------------------------------- TCP state
def P(src, dst, flags):
    return dict(src=src, dst=dst, syn="S" in flags, ack="A" in flags, fin="F" in flags, rst="R" in flags)


A, B = "10.0.0.1", "8.8.8.8"


def test_tcp_s0_with_retransmitted_syns():
    r = fx.classify_tcp([P(A, B, "S"), P(A, B, "S"), P(A, B, "S")])
    assert r["state"] == "S0" and r["syn_count"] == 3 and r["synack_count"] == 0
    assert r["initiator"] == A and r["initiator_assumed"] is False


def test_tcp_rej():
    r = fx.classify_tcp([P(A, B, "S"), P(B, A, "RA")])
    assert r["state"] == "REJ" and r["rst_by"] == "resp"


def test_tcp_est_fin():
    r = fx.classify_tcp([P(A, B, "S"), P(B, A, "SA"), P(A, B, "A"), P(A, B, "PA"),
                         P(B, A, "FA"), P(A, B, "FA"), P(B, A, "A")])
    assert r["state"] == "EST_FIN" and r["fin_by"] == "resp/orig" and r["synack_count"] == 1


def test_tcp_est_rst_records_sender():
    r = fx.classify_tcp([P(A, B, "S"), P(B, A, "SA"), P(A, B, "A"), P(A, B, "PA"), P(A, B, "RA")])
    assert r["state"] == "EST_RST" and r["rst_by"] == "orig"
    r = fx.classify_tcp([P(A, B, "S"), P(B, A, "SA"), P(A, B, "A"), P(B, A, "FA"), P(B, A, "R")])
    assert r["state"] == "EST_RST" and r["rst_by"] == "resp" and r["fin_by"] == "resp"


def test_tcp_est_open():
    r = fx.classify_tcp([P(A, B, "S"), P(B, A, "SA"), P(A, B, "A"), P(A, B, "PA")])
    assert r["state"] == "EST_OPEN"


def test_tcp_partial_without_syn_assumes_first_packet():
    r = fx.classify_tcp([P(B, A, "PA"), P(A, B, "A")])
    assert r["state"] == "PARTIAL" and r["initiator"] == B and r["initiator_assumed"] is True


def test_tcp_initiator_is_first_pure_syn_not_first_packet():
    # gói đầu là ACK lạc từ B, sau đó A mới gửi SYN
    r = fx.classify_tcp([P(B, A, "A"), P(A, B, "S"), P(B, A, "SA"), P(A, B, "A"), P(A, B, "FA")])
    assert r["initiator"] == A and r["state"] == "EST_FIN"


def test_tcp_synack_without_final_ack():
    r = fx.classify_tcp([P(A, B, "S"), P(B, A, "SA")])
    assert r["state"] == "SYN_ACK_NO_ACK"


def test_tcp_empty():
    assert fx.classify_tcp([])["state"] == "PARTIAL"


# ----------------------------------------------------------------------- DNS
def test_split_dns_answers_excludes_additional_glue():
    # Frame 39 S01: 17 answers (1 CNAME + 16 A), 4 NS authority, 4 A additional (glue)
    types = "5|" + "|".join(["1"] * 16) + "|2|2|2|2|1|1|1|1"
    names = "|".join(["cr-tools.clients.google.com"] + ["clients.l.google.com"] * 16 + ["google.com"] * 4
                     + ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"])
    a_vals = "|".join([f"74.125.232.{i}" for i in range(16)] + ["216.239.32.10", "216.239.34.10",
                                                                   "216.239.36.10", "216.239.38.10"])
    ans_a, ans_c, other = fx.split_dns_answers("17", types, names, a_vals, "clients.l.google.com")
    assert len(ans_a) == 16 and "216.239.32.10" not in ans_a
    assert ans_c == ["clients.l.google.com"]
    assert other == ["216.239.32.10", "216.239.34.10", "216.239.36.10", "216.239.38.10"]


def test_split_dns_answers_nxdomain():
    assert fx.split_dns_answers("0", "6", "<Root>", "", "") == ([], [], [])


def _dns_pkt(frame, t, src, dst, sport, dport, did, resp, qname, rcode="", nans="0", types="", names="", a="",
             response_to=""):
    return {"frame.number": str(frame), "frame.time_epoch": t, "frame.time_relative": t, "ip.src": src,
            "ip.dst": dst, "ip.id": "", "udp.srcport": sport, "udp.dstport": dport, "udp.stream": "0",
            "tcp.srcport": "", "tcp.dstport": "", "dns.id": did, "dns.flags.response": "1" if resp else "0",
            "dns.qry.name": qname, "dns.qry.type": "1", "dns.flags.rcode": rcode, "dns.count.answers": nans,
            "dns.resp.type": types, "dns.resp.name": names, "dns.a": a, "dns.cname": "",
            "dns.response_to": response_to}


def test_build_dns_dedup_retransmission_orphan():
    pk = [
        _dns_pkt(22, "100.000000", A, "147.32.80.9", "1025", "53", "0x1", False, "wpad"),
        _dns_pkt(23, "100.000006", A, "147.32.80.9", "1025", "53", "0x1", False, "wpad"),       # trùng capture
        _dns_pkt(24, "100.000600", "147.32.80.9", A, "53", "1025", "0x1", True, "wpad", rcode="3",
                 types="6", names="<Root>", response_to="22"),
        _dns_pkt(30, "101.000000", A, "147.32.80.9", "1025", "53", "0x2", False, "x.ru"),
        _dns_pkt(31, "102.000000", A, "147.32.80.9", "1025", "53", "0x2", False, "x.ru"),       # retransmission thật
        _dns_pkt(40, "103.000000", "1.2.3.4", A, "53", "1030", "0x9", True, "orphan.com", rcode="0",
                 nans="1", types="1", names="orphan.com", a="5.6.7.8", response_to=""),
    ]
    queries, matched, orphans, st = fx.build_dns(pk, "147.32.80.9", True)
    assert st["queries_raw"] == 4 and st["queries_capture_dup"] == 1 and st["queries_unique"] == 3
    assert st["queries_retransmission"] == 1
    assert queries[0]["dup_frames"] == ["23"] and "22" in matched
    assert st["nxdomain_queries"] == 1 and st["queries_no_response"] == 2
    assert [o["frame"] for o in orphans] == ["40"]
    rows = fx.dns_rows(queries, matched, "147.32.80.9", "t.pcap")
    assert rows[0]["rcode"] == "NXDOMAIN" and rows[0]["dup_frames"] == "23"
    assert rows[0]["resolver_type"] == "internal"
    assert "retransmission-of=30" in rows[2]["notes"] and "no-response" in rows[2]["notes"]
    agg = {r["query"]: r for r in fx.dns_aggregate(rows)}
    assert agg["wpad"]["query_count"] == 1          # query trùng không bị đếm 2 lần
    assert agg["x.ru"]["query_count"] == 2 and agg["x.ru"]["retransmissions"] == 1


def test_match_dns_response_to_points_to_dup_frame():
    q = [dict(frame="22", dup_frames=["23"], dns_id="1", qname="a", src_ip=A, src_port="1", dst_ip=B,
              dst_port="53", t=Decimal(1))]
    r = [dict(frame="24", response_to="23", dns_id="1", qname="a", src_ip=B, src_port="53", dst_ip=A,
              dst_port="1", t=Decimal(2))]
    matched, orphans = fx.match_dns(q, r, True)
    assert matched["22"]["frame"] == "24" and orphans == []


def test_match_dns_fallback_without_response_to():
    q = [dict(frame="1", dup_frames=[], dns_id="7", qname="a.com", src_ip=A, src_port="1100", dst_ip=B,
              dst_port="53", t=Decimal(1)),
         dict(frame="2", dup_frames=[], dns_id="7", qname="a.com", src_ip=A, src_port="1200", dst_ip=B,
              dst_port="53", t=Decimal(1))]
    r = [dict(frame="3", dns_id="7", qname="a.com", src_ip=B, src_port="53", dst_ip=A, dst_port="1200",
              t=Decimal(2)),
         dict(frame="4", dns_id="7", qname="a.com", src_ip=B, src_port="53", dst_ip=A, dst_port="9999",
              t=Decimal(2))]
    matched, orphans = fx.match_dns(q, r, False)
    assert matched == {"2": r[0]} and orphans == [r[1]]


# --------------------------------------------------------------- connections
def _tcp_pkt(frame, t, src, dst, sport, dport, flags, ipid, seq="1000", retrans=""):
    return {"frame.number": str(frame), "frame.time_epoch": t, "frame.time_relative": t, "frame.len": "62",
            "ip.src": src, "ip.dst": dst, "ip.id": ipid, "tcp.stream": "0", "tcp.srcport": sport,
            "tcp.dstport": dport, "tcp.flags.syn": "1" if "S" in flags else "0",
            "tcp.flags.ack": "True" if "A" in flags else "False", "tcp.flags.reset": "1" if "R" in flags else "0",
            "tcp.flags.fin": "1" if "F" in flags else "0", "tcp.seq_raw": seq, "tcp.len": "0",
            "tcp.flags": flags, "tcp.analysis.retransmission": retrans, "udp.stream": "", "udp.srcport": "",
            "udp.dstport": "", "udp.length": ""}


def test_build_connections_counts_capture_duplicates():
    pk = [_tcp_pkt(1, "10.000000", A, B, "1566", "25", "S", "0x0ad4"),
          _tcp_pkt(2, "10.000008", A, B, "1566", "25", "S", "0x0ad4", retrans="1"),
          _tcp_pkt(3, "13.000000", A, B, "1566", "25", "S", "0x0adf", retrans="1"),
          _tcp_pkt(4, "13.000010", A, B, "1566", "25", "S", "0x0adf", retrans="1")]
    rows, dups = fx.build_connections(pk, "S01", "t.pcap", {A})
    r = rows[0]
    assert r["tcp_state"] == "S0" and r["packets"] == 4 and r["packets_dedup"] == 2
    assert r["dup_suspect_count"] == 2 and r["retrans_count"] == 3 and r["syn_count"] == 4
    assert r["first_frame"] == "1" and r["last_frame"] == "4" and r["ts_start_utc"].endswith("Z")
    assert r["rel_start"] == "10.000000" and r["from_infected"] == "yes" and dups["TCP"] == 2
    top = fx.top_destinations(rows, {A})
    assert top[0]["streams"] == 1 and top[0]["failed_tcp_s0_rej"] == 1 and top[0]["dst_ports"] == "25(1)"


# ---------------------------------------------------------------------- Zeek
def test_parse_zeek_conn_json_and_tsv(tmp_path):
    j = tmp_path / "conn.log"
    j.write_text(json.dumps({"ts": 10.0, "uid": "C1", "id.orig_h": A, "id.orig_p": 1566, "id.resp_h": B,
                             "id.resp_p": 25, "proto": "tcp", "conn_state": "S0", "history": "S"}) + "\n")
    assert fx.parse_zeek_conn(str(j))[0]["orig_p"] == "1566"
    t = tmp_path / "conn_tsv.log"
    t.write_text("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\thistory\n"
                 f"10.0\tC1\t{A}\t1566\t{B}\t25\ttcp\tS0\tS\n")
    z = fx.parse_zeek_conn(str(t))
    assert z[0]["proto"] == "TCP" and z[0]["conn_state"] == "S0"


def test_crosscheck_one_stream_two_zeek_conns():
    conn = dict(conn_id="S01-TCP0", protocol="TCP", stream="0", ts_start_utc="x", src_ip=A, src_port="1566",
                dst_ip=B, dst_port="25", tcp_state="S0", _t0="10.0", _t1="19.0")
    z = [dict(uid="C1", ts=10.0, proto="TCP", orig_h=A, orig_p="1566", resp_h=B, resp_p="25", conn_state="S0", history="S"),
         dict(uid="C2", ts=19.0, proto="TCP", orig_h=A, orig_p="1566", resp_h=B, resp_p="25", conn_state="S0", history="S")]
    out = fx.crosscheck_zeek([conn], z)[0]
    assert out["zeek_start_match_uid"] == "C1" and out["zeek_conns_in_stream_span"] == 2 and out["match_type"] == "1:2"


# ------------------------------------------------------- xử lý lỗi công cụ
def _fake_tshark():
    t = object.__new__(fx.Tshark)
    t.bin, t.capinfos, t.timeout, t.version, t._fields, t.warnings = "x", None, 30, "TShark 0.0", None, []
    return t


def test_exec_raises_on_nonzero_return():
    t = _fake_tshark()
    with pytest.raises(fx.ToolError, match="returncode=1"):
        t._exec([sys.executable, "-c", "import sys; sys.stderr.write('boom\\n'); sys.exit(1)"])


def test_exec_cut_short_is_warning_and_root_line_ignored():
    t = _fake_tshark()
    code = ("import sys; print('data'); sys.stderr.write('Running as user \"root\" and group \"root\".\\n'"
            "'tshark: The file \"x.pcap\" appears to have been cut short in the middle of a packet.\\n'); sys.exit(2)")
    assert t._exec([sys.executable, "-c", code]).strip() == "data"
    assert len(t.warnings) == 1 and "cut short" in t.warnings[0]


def test_exec_timeout_and_missing_binary():
    t = _fake_tshark()
    t.timeout = 1
    with pytest.raises(fx.ToolError, match="quá thời gian"):
        t._exec([sys.executable, "-c", "import time; time.sleep(5)"])
    with pytest.raises(fx.ToolError, match="Không chạy được"):
        t._exec([str(Path("/nonexistent/tshark_xyz"))])


def test_require_reports_missing_field_and_version():
    t = _fake_tshark()
    t._fields = {"frame.number"}
    with pytest.raises(fx.FieldMissingError, match=r"udp\.stream.*TShark 0\.0"):
        t.require(["frame.number", "udp.stream"])


def test_check_pcap_rejects_empty_and_missing(tmp_path):
    empty = tmp_path / "e.pcap"
    empty.write_bytes(b"")
    with pytest.raises(ValueError):
        fx.check_pcap(str(empty))
    with pytest.raises(FileNotFoundError):
        fx.check_pcap(str(tmp_path / "missing.pcap"))


def test_main_exit_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(fx, "find_tool", lambda *a, **k: None)
    assert fx.main([str(tmp_path / "x.pcap"), "--out", str(tmp_path)]) == 3
    monkeypatch.setattr(fx, "find_tool", lambda *a, **k: sys.executable)
    assert fx.main([str(tmp_path / "x.pcap"), "--out", str(tmp_path)]) == 4


# ------------------------------------------- tích hợp: PCAP tổng hợp bằng scapy
def test_integration_synthetic_pcap(tmp_path):
    scapy_all = pytest.importorskip("scapy.all")
    tshark = fx.find_tool("tshark", "TSHARK")
    if not tshark:
        pytest.skip("không có tshark")
    Ether, IP, TCP, UDP = scapy_all.Ether, scapy_all.IP, scapy_all.TCP, scapy_all.UDP
    DNS, DNSQR, DNSRR = scapy_all.DNS, scapy_all.DNSQR, scapy_all.DNSRR
    inf, srv, res = "147.32.84.165", "93.184.216.34", "147.32.80.9"
    pk = []

    def add(p, t):
        p.time = t
        pk.append(p)

    e = Ether(src="08:00:27:b5:b7:19", dst="00:1e:49:db:19:c3")
    # stream 0: S0 với SYN bị nhân đôi do capture (+8 µs) và thử lại sau 3 s
    for t, ipid in ((1000.0, 10), (1003.0, 11)):
        s = e / IP(src=inf, dst=srv, id=ipid) / TCP(sport=1566, dport=25, flags="S", seq=500)
        add(s, t)
        add(s.copy(), t + 0.000008)
    # stream 1: bắt tay đủ + FIN
    add(e / IP(src=inf, dst=srv, id=20) / TCP(sport=1600, dport=80, flags="S", seq=100), 1010.0)
    add(e / IP(src=srv, dst=inf, id=21) / TCP(sport=80, dport=1600, flags="SA", seq=900, ack=101), 1010.1)
    add(e / IP(src=inf, dst=srv, id=22) / TCP(sport=1600, dport=80, flags="A", seq=101, ack=901), 1010.2)
    add(e / IP(src=inf, dst=srv, id=23) / TCP(sport=1600, dport=80, flags="FA", seq=101, ack=901), 1010.3)
    add(e / IP(src=srv, dst=inf, id=24) / TCP(sport=80, dport=1600, flags="FA", seq=901, ack=102), 1010.4)
    # stream 2: REJ
    add(e / IP(src=inf, dst=srv, id=30) / TCP(sport=1700, dport=139, flags="S", seq=1), 1020.0)
    add(e / IP(src=srv, dst=inf, id=31) / TCP(sport=139, dport=1700, flags="RA", seq=0, ack=2), 1020.1)
    # DNS: query nhân đôi + response có answer CNAME/A và additional glue
    q = e / IP(src=inf, dst=res, id=40) / UDP(sport=1025, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname="ex.com"))
    add(q, 1030.0)
    add(q.copy(), 1030.000006)
    r = e / IP(src=res, dst=inf, id=41) / UDP(sport=53, dport=1025) / DNS(
        id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="ex.com"),
        an=[DNSRR(rrname="ex.com", type="CNAME", rdata="cdn.ex.com"), DNSRR(rrname="cdn.ex.com", type="A", rdata=srv)],
        ar=[DNSRR(rrname="ns1.ex.com", type="A", rdata="9.9.9.9")])
    add(r, 1030.01)
    pcap = tmp_path / "synthetic.pcap"
    scapy_all.wrpcap(str(pcap), pk)
    out = tmp_path / "out"
    rc = fx.main([str(pcap), "--scenario", "T", "--infected", inf, "--out", str(out), "--http-decode-ports", ""])
    assert rc == 0
    conns = list(csv.DictReader(open(out / "network_connections.csv", encoding="utf-8")))
    states = {c["dst_port"]: c for c in conns if c["protocol"] == "TCP"}
    assert states["25"]["tcp_state"] == "S0" and states["25"]["dup_suspect_count"] == "2"
    assert states["25"]["packets_dedup"] == "2"
    assert states["80"]["tcp_state"] == "EST_FIN" and states["139"]["tcp_state"] == "REJ"
    assert states["25"]["ts_start_utc"] == "1970-01-01T00:16:40.000000Z"
    with gzip.open(out / "dns_queries_full.csv.gz", "rt", encoding="utf-8") as f:
        dq = list(csv.DictReader(f))
    assert len(dq) == 1 and dq[0]["answers_A"] == srv and dq[0]["answers_CNAME"] == "cdn.ex.com"
    assert dq[0]["additional_A_count"] == "1" and dq[0]["dup_frames"] != ""
    agg = list(csv.DictReader(open(out / "dns_findings.csv", encoding="utf-8")))
    assert agg[0]["query_count"] == "1" and "9.9.9.9" not in agg[0]["answers_A"]
    summ = json.loads((out / "extract_summary.json").read_text(encoding="utf-8"))
    assert summ["tcp_streams"] == 3 and summ["dns"]["queries_capture_dup"] == 1
    meta = (out / "metadata.txt").read_text(encoding="utf-8")
    assert "First packet (UTC): 1970-01-01T00:16:40.000000Z" in meta and str(tmp_path) not in meta


# ---------------------------------------------------------------- HTTP detection
def test_http_detection_dissector_vs_payload_heuristic():
    labels = {"10": "HTTP", "20": "IRC", "30": "KRB5"}
    assert fx.http_detection("10", {"10"}, labels) == ("dissector", "HTTP")
    assert fx.http_detection("20", {"10"}, labels) == ("payload_heuristic", "IRC")
    assert fx.http_detection("30", {"10"}, labels) == ("payload_heuristic", "KRB5")
    assert fx.http_detection("40", {"10"}, labels) == ("payload_heuristic", "")


def test_http_rows_detection_columns():
    base = {"frame.time_epoch": "1000.0", "frame.time_relative": "0.0", "tcp.stream": "0",
            "ip.src": "10.0.0.1", "ip.dst": "192.0.2.1", "tcp.srcport": "1025", "http.request.method": "POST",
            "http.host": "192.0.2.1", "http.user_agent": "Mozilla", "http.content_length_header": ""}
    reqs = [dict(base, **{"frame.number": "5", "tcp.dstport": "80", "http.request.uri": "/a"}),
            dict(base, **{"frame.number": "9", "tcp.dstport": "6667", "http.request.uri": "/?00ff"})]
    rows = fx.http_rows(reqs, [], "x.pcap", {"10.0.0.1"}, {"5"}, {"5": "HTTP", "9": "IRC"})
    assert [(r["detection"], r["wireshark_label"]) for r in rows] == [("dissector", "HTTP"),
                                                                     ("payload_heuristic", "IRC")]
    assert set(fx.HTTP_HEADER) >= {"detection", "wireshark_label"}
    # không truyền tập mặc định (vd. --http-decode-ports "") -> coi như dissector
    assert fx.http_rows(reqs[:1], [], "x.pcap", {"10.0.0.1"})[0]["detection"] == "dissector"
