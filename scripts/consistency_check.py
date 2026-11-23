#!/usr/bin/env python3
"""
consistency_check.py — đối chiếu độc lập output của forensics_extract.py với TShark/capinfos.

Không import forensics_extract: mọi giá trị "độc lập" lấy trực tiếp từ capinfos / tshark
(-Y filter, -z thống kê) và một bộ đếm gói trùng viết riêng. Kết quả ghi ra
<out>/consistency_values.csv (tất định) để dán vào data_consistency_check.md.

  python scripts/consistency_check.py <pcap> --out analysis/network-forensics/S01 \
      --infected 147.32.84.165 [--repo-root .]
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

WIN = r"C:\Program Files\Wireshark"


def tool(name, env):
    for c in (os.environ.get(env), shutil.which(name), os.path.join(WIN, name + ".exe")):
        if c and os.path.isfile(c):
            return c
    sys.exit(f"Không tìm thấy {name}")


def run(cmd, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=3600)
    if p.returncode != 0:
        sys.exit(f"Lỗi ({p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p.stdout


def count(ts, pcap, flt, extra=()):
    out = run([ts, "-r", pcap, "-n", *extra, "-Y", flt, "-T", "fields", "-e", "frame.number"])
    return sum(1 for l in out.splitlines() if l.strip())


def distinct(ts, pcap, field):
    out = run([ts, "-r", pcap, "-n", "-T", "fields", "-e", field])
    return len({l.strip() for l in out.splitlines() if l.strip()})


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def csv_rows(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--out", required=True)
    ap.add_argument("--infected", default="147.32.84.165")
    ap.add_argument("--repo-root", default=".")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    ts, ci = tool("tshark", "TSHARK"), tool("capinfos", "CAPINFOS")
    O, R, pcap, inf = a.out, a.repo_root, a.pcap, a.infected
    res = []

    def add(metric, script_val, indep_val, source, note=""):
        match = "yes" if str(script_val) == str(indep_val) else "no"
        res.append(dict(metric=metric, script_value=script_val, independent_value=indep_val,
                        match=match, independent_source=source, note=note))

    summ = json.load(open(os.path.join(O, "extract_summary.json"), encoding="utf-8"))
    meta = open(os.path.join(O, "metadata.txt"), encoding="utf-8").read()

    # 1. capinfos (TZ=UTC)
    cap = run([ci, "-c", "-a", "-e", "-u", "-M", pcap], env=dict(os.environ, TZ="UTC"))
    g = lambda k: re.search(rf"{k}:\s+(.+)", cap).group(1).strip()
    add("packets", summ["packets"], g("Number of packets"), "capinfos -c -M")
    to_iso = lambda s: s.replace(" ", "T") + "Z"
    add("first_packet_utc", summ["first_utc"], to_iso(g("Earliest packet time")), "capinfos -a (TZ=UTC)")
    add("last_packet_utc", summ["last_utc"], to_iso(g("Latest packet time")), "capinfos -e (TZ=UTC)")
    add("duration_s", re.search(r"Duration \(s\): (\S+)", meta).group(1), g("Capture duration").split()[0], "capinfos -u")

    # 2. streams
    conns = csv_rows(os.path.join(O, "network_connections.csv"))
    add("tcp_streams", sum(c["protocol"] == "TCP" for c in conns), distinct(ts, pcap, "tcp.stream"),
        "tshark -T fields -e tcp.stream | sort -u")
    add("udp_streams", sum(c["protocol"] == "UDP" for c in conns), distinct(ts, pcap, "udp.stream"),
        "tshark -T fields -e udp.stream | sort -u")

    # 3. protocol hierarchy: so file của script với lần chạy -z io,phs mới
    phs_new = run([ts, "-r", pcap, "-n", "-q", "-z", "io,phs"])
    phs_old = open(os.path.join(O, "protocol_hierarchy.txt"), encoding="utf-8").read()
    norm = lambda t: [l.strip() for l in t.splitlines() if re.search(r"frames:\d+", l)]
    add("protocol_hierarchy_lines_identical", len(norm(phs_old)), len(norm(phs_new)) if norm(phs_old) == norm(phs_new) else "DIFF",
        "tshark -qz io,phs")

    # 4. conv,ip top 10 theo bytes so với top_destinations (packets mọi giao thức IP)
    conv = run([ts, "-r", pcap, "-n", "-q", "-z", f"conv,ip,ip.addr=={inf}"])
    pairs = []
    for l in conv.splitlines():
        m = re.match(r"\s*(\S+)\s+<->\s+(\S+)\s+(\d+)\s+(\S+ \S+)\s+(\d+)\s+(\S+ \S+)\s+(\d+)\s+(\S+ \S+)", l)
        if m:
            other = m.group(2) if m.group(1) == inf else m.group(1)
            pairs.append((other, int(m.group(7))))
    top = {r["dst_ip"]: r for r in csv_rows(os.path.join(O, "top_destinations.csv"))}
    agg_pk = defaultdict(int)
    for c in conns:
        if inf in (c["src_ip"], c["dst_ip"]):
            agg_pk[c["dst_ip"] if c["src_ip"] == inf else c["src_ip"]] += int(c["packets"])
    for other, frames in sorted(pairs, key=lambda x: -x[1])[:10]:
        add(f"conv_ip_frames[{other}]", agg_pk.get(other, 0), frames, "tshark -qz conv,ip (Frames tổng 2 chiều)",
            f"top_destinations streams={top.get(other, {}).get('streams', '-')}")

    # 5. DNS
    d = summ["dns"]
    q_all = count(ts, pcap, "dns.flags.response==0")
    q_icmp = count(ts, pcap, "dns.flags.response==0 && icmp")
    add("dns_query_packets (non-ICMP)", d["queries_raw"], q_all - q_icmp, "tshark -Y dns.flags.response==0 trừ bản trong ICMP",
        f"tổng kể cả ICMP-quoted={q_all}, trong ICMP={q_icmp}")
    r_all = count(ts, pcap, "dns.flags.response==1")
    r_icmp = count(ts, pcap, "dns.flags.response==1 && icmp")
    add("dns_response_packets (non-ICMP)", d["responses_raw"], r_all - r_icmp, "tshark -Y dns.flags.response==1 trừ ICMP",
        f"tổng kể cả ICMP-quoted={r_all}")
    add("dns_nxdomain_responses", d["nxdomain_responses_raw"], count(ts, pcap, "dns.flags.rcode==3 && !icmp"),
        "tshark -Y dns.flags.rcode==3")
    dq = csv_rows(os.path.join(O, "dns_queries_full.csv.gz"))
    add("dns_unique_queries = queries_raw - capture_dup", len(dq), d["queries_raw"] - d["queries_capture_dup"],
        "phép trừ từ bộ đếm thô")
    agg = csv_rows(os.path.join(O, "dns_findings.csv"))
    add("dns_findings sum(query_count)", sum(int(x["query_count"]) for x in agg), len(dq), "dns_queries_full.csv.gz rows")
    retr = count(ts, pcap, "dns.flags.response==0 && dns.retransmission && !icmp")
    add("dns_query_retrans_flag (tshark) = capture_dup + real_retrans", retr,
        d["queries_capture_dup"] + d["queries_retransmission"], "tshark -Y dns.retransmission",
        "tshark gắn cờ cả bản sao do capture lẫn gửi lại thật")

    # 6. HTTP / SMTP / IRC
    http = csv_rows(os.path.join(O, "http_requests.csv"))
    add("http_requests (decode-as 6667,88)", len(http),
        count(ts, pcap, "http.request", ["-d", "tcp.port==6667,http", "-d", "tcp.port==88,http"]),
        "tshark -d tcp.port==6667,http -d tcp.port==88,http -Y http.request",
        f"mặc định không decode-as: {count(ts, pcap, 'http.request')}")
    n_def = count(ts, pcap, "http.request")
    add("http_requests detection=dissector", sum(h["detection"] == "dissector" for h in http), n_def,
        "tshark -Y http.request (không decode-as)")
    add("http_requests detection=payload_heuristic (port 6667+88)",
        sum(h["detection"] == "payload_heuristic" for h in http),
        count(ts, pcap, "http.request && tcp.port in {6667,88}", ["-d", "tcp.port==6667,http", "-d", "tcp.port==88,http"])
        - count(ts, pcap, "http.request && tcp.port in {6667,88}"),
        "(decode-as) − (mặc định) trên tcp.port 6667/88",
        "1361 dissector + 32 payload_heuristic = 1393")
    misc = csv_rows(os.path.join(O, "irc_smtp_activity.csv"))
    add("smtp_command_packets", sum(m["proto"] == "SMTP" and m["kind"] == "request" for m in misc),
        count(ts, pcap, "smtp.req.command"), "tshark -Y smtp.req.command",
        f"smtp.req (kể cả dòng AUTH base64 không ghi ra)={count(ts, pcap, 'smtp.req')}")
    add("smtp_235", sum("235" in m["response_code"].split("|") for m in misc), count(ts, pcap, "smtp.response.code==235"),
        "tshark -Y smtp.response.code==235")
    add("smtp_535", sum("535" in m["response_code"].split("|") for m in misc), count(ts, pcap, "smtp.response.code==535"),
        "tshark -Y smtp.response.code==535")
    add("irc_packets", sum(m["proto"] == "IRC" for m in misc), count(ts, pcap, "irc"), "tshark -Y irc")
    add("irc_commands NICK/USER/JOIN/PRIVMSG", 0,
        count(ts, pcap, 'tcp.payload contains "NICK " || tcp.payload contains "USER " || '
                        'tcp.payload contains "JOIN #" || tcp.payload contains "PRIVMSG"'),
        "tshark -Y tcp.payload contains ...")

    # 7. SHA-256
    real = sha256(pcap)
    add("sha256 pcap (tính lại)", summ["sha256"], real, "sha256 trực tiếp file PCAP")
    man = csv_rows(os.path.join(R, "datasets", "dataset_manifest.csv"))
    add("sha256 datasets/dataset_manifest.csv", man[0]["sha256"], real, "so với hash tính lại")
    lam = csv_rows(os.path.join(R, "reports", "week1", "lam", "dataset_manifest.csv"))
    add("sha256 reports/week1/lam/dataset_manifest.csv", lam[0]["pcap_sha256"], real, "so với hash tính lại")
    add("packet_count reports/week1/lam/dataset_manifest.csv", lam[0]["packet_count"], summ["packets"], "so với capinfos")
    fnd = open(os.path.join(R, "evidence", "findings", "FND-001.md"), encoding="utf-8").read()
    m = re.search(r"\b([0-9a-f]{64})\b", fnd)
    add("sha256 evidence/findings/FND-001.md", m.group(1) if m else "", real, "so với hash tính lại")

    # 8. gói trùng — bộ đếm độc lập theo (ip.id, src, dst, proto, ip.len, ip.checksum)
    out = run([ts, "-r", pcap, "-n", "-Y", "ip", "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.id", "-e", "ip.src",
               "-e", "ip.dst", "-e", "ip.proto", "-e", "ip.len", "-e", "ip.checksum", "-e", "ip.src"])
    last = {}
    dt_bins = Counter()
    for l in out.splitlines():
        p = l.split("\t")
        if len(p) < 7:
            continue
        k, t = tuple(p[1:7]), float(p[0])
        if k in last:
            dt = t - last[k]
            dt_bins["<1ms" if dt < 0.001 else "1ms-2s" if dt < 2 else ">=2s"] += 1
        last[k] = t
    add("dup_packets_<1ms (TCP+UDP)", sum(summ["dup_suspect_packets"].values()), dt_bins["<1ms"],
        "đếm độc lập theo ip.id+src+dst+proto+len+checksum (mọi giao thức IP)",
        f"1ms-2s={dt_bins['1ms-2s']}, >=2s={dt_bins['>=2s']} (>=2s nhiều khả năng là ip.id lặp lại tự nhiên)")

    # 9. đơn vị Zeek vs stream cho 2 đích port 25 / 4506 — quy tắc tách start+5s
    for dst, port, zeek in (("209.85.225.27", "25", 1930), ("212.117.174.7", "4506", 1804)):
        o = run([ts, "-r", pcap, "-n", "-Y", f"ip.dst=={dst} && tcp.dstport=={port}", "-T", "fields",
                 "-e", "tcp.stream", "-e", "frame.time_epoch"])
        st = defaultdict(list)
        for l in o.splitlines():
            s, t = l.split("\t")
            st[s].append(float(t))
        n = 0
        for v in st.values():
            v.sort()
            start = v[0]
            n += 1
            for t in v[1:]:
                if t - start > 5:
                    start, n = t, n + 1
        add(f"streams {dst}:{port}", len(st), next(r["streams"] for r in top.values() if r["dst_ip"] == dst),
            "tshark tcp.stream distinct", "")
        add(f"zeek-like conns {dst}:{port} (tách khi gói > start+5s)", n, zeek, "Zeek conn.log của Quý (FND-002/003)",
            "khớp => mỗi stream = 2 Zeek conn")

    path = os.path.join(O, "consistency_values.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(res[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(res)
    for r in res:
        print(f"| {r['metric']} | {r['script_value']} | {r['independent_value']} | {r['match']} | {r['note']}")
    print(f"-> {path}")


if __name__ == "__main__":
    main()
