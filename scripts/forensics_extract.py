#!/usr/bin/env python3
"""
forensics_extract.py — Người 1 (Network Forensics) — Đề tài 08
Trích xuất evidence từ 1 PCAP bằng tshark, sinh các file bàn giao:
  metadata.txt, protocol_hierarchy.txt, conversations_ip.txt, conversations_tcp.txt,
  network_connections.csv, dns_findings.csv, http_requests.csv, irc_smtp_activity.csv,
  top_destinations.csv
Yêu cầu: Wireshark/tshark trong PATH (Windows: C:\\Program Files\\Wireshark), Python 3.8+.
Cách chạy:
  python forensics_extract.py <file.pcap> --scenario S01 --infected 147.32.84.165 --out analysis/network-forensics/S01
"""
import argparse, csv, hashlib, math, os, shutil, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

def tshark_bin():
    for c in ("tshark", r"C:\Program Files\Wireshark\tshark.exe"):
        if shutil.which(c) or os.path.exists(c):
            return shutil.which(c) or c
    sys.exit("Không tìm thấy tshark. Cài Wireshark và thêm vào PATH.")

TSHARK = None

def run(args):
    return subprocess.run([TSHARK] + args, capture_output=True, text=True, errors="replace").stdout

def fields(pcap, display_filter, flds):
    args = ["-r", pcap, "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
            "-E", "aggregator=|"]
    if display_filter:
        args += ["-Y", display_filter]
    for f in flds:
        args += ["-e", f]
    out = run(args)
    for line in out.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(flds) - len(parts))
        yield dict(zip(flds, parts))

def iso(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    except ValueError:
        return ""

def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def write_csv(path, rows, header):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  -> {path} ({len(rows)} dòng)")

def main():
    global TSHARK
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--scenario", default="S01")
    ap.add_argument("--infected", default="", help="IP máy nhiễm theo README dataset, phân cách bằng dấu phẩy")
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    TSHARK = tshark_bin()
    os.makedirs(a.out, exist_ok=True)
    pcap_name = os.path.basename(a.pcap)
    infected = set(x.strip() for x in a.infected.split(",") if x.strip())
    sid = a.scenario

    print("[1/7] Metadata + SHA-256")
    capinfos = shutil.which("capinfos") or next(
        (p for p in (os.path.join(os.path.dirname(TSHARK), n) for n in ("capinfos.exe", "capinfos")) if os.path.exists(p)), None)
    meta = subprocess.run([capinfos, a.pcap], capture_output=True, text=True, errors="replace").stdout if capinfos else "(không tìm thấy capinfos)\n"
    with open(os.path.join(a.out, "metadata.txt"), "w", encoding="utf-8") as f:
        f.write(f"PCAP: {pcap_name}\nSHA-256: {sha256(a.pcap)}\n\n{meta}")

    print("[2/7] Protocol hierarchy + conversations")
    for name, z in [("protocol_hierarchy.txt", "io,phs"), ("conversations_ip.txt", "conv,ip"),
                    ("conversations_tcp.txt", "conv,tcp"), ("conversations_udp.txt", "conv,udp"),
                    ("endpoints_ip.txt", "endpoints,ip")]:
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as f:
            f.write(run(["-r", a.pcap, "-n", "-q", "-z", z]))

    print("[3/7] Gom connection theo TCP/UDP stream")
    conns = {}
    flds = ["frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
            "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack",
            "tcp.flags.reset", "tcp.flags.fin", "udp.stream", "udp.srcport", "udp.dstport"]
    for p in fields(a.pcap, "ip and (tcp or udp)", flds):
        if p["tcp.stream"]:
            key = ("TCP", p["tcp.stream"])
        elif p["udp.stream"]:
            key = ("UDP", p["udp.stream"])
        else:
            continue
        c = conns.get(key)
        if c is None:
            # Chiều kết nối = gói đầu tiên quan sát được (với TCP ưu tiên SYN không ACK)
            c = conns[key] = dict(proto=key[0], stream=key[1], first_frame=p["frame.number"],
                                  t0=float(p["frame.time_epoch"]), t1=float(p["frame.time_epoch"]),
                                  src=p["ip.src"], dst=p["ip.dst"],
                                  sport=p["tcp.srcport"] or p["udp.srcport"],
                                  dport=p["tcp.dstport"] or p["udp.dstport"],
                                  pkts=0, bytes_out=0, bytes_in=0, syn=False, synack=False,
                                  rst=False, fin=False)
            if key[0] == "TCP":
                c["syn"] = p["tcp.flags.syn"] in ("1", "True") and p["tcp.flags.ack"] in ("0", "False")
        c["t1"] = float(p["frame.time_epoch"])
        c["pkts"] += 1
        n = int(p["frame.len"] or 0)
        if p["ip.src"] == c["src"]:
            c["bytes_out"] += n
        else:
            c["bytes_in"] += n
        if key[0] == "TCP":
            if p["tcp.flags.syn"] in ("1", "True") and p["tcp.flags.ack"] in ("1", "True"):
                c["synack"] = True
            if p["tcp.flags.reset"] in ("1", "True"):
                c["rst"] = True
            if p["tcp.flags.fin"] in ("1", "True"):
                c["fin"] = True
    rows = []
    for c in sorted(conns.values(), key=lambda x: x["t0"]):
        if c["proto"] == "TCP":
            state = ("S0-no-reply" if c["syn"] and not c["synack"] and not c["rst"] else
                     "REJ" if c["syn"] and not c["synack"] and c["rst"] else
                     "ESTABLISHED+FIN" if c["synack"] and c["fin"] else
                     "ESTABLISHED+RST" if c["synack"] and c["rst"] else
                     "ESTABLISHED" if c["synack"] else "PARTIAL(no SYN seen)")
            filt = f"tcp.stream eq {c['stream']}"
        else:
            state = "-"
            filt = f"udp.stream eq {c['stream']}"
        rows.append(dict(
            conn_id=f"{sid}-{c['proto']}{c['stream']}", pcap=pcap_name, first_frame=c["first_frame"],
            ts_start=iso(c["t0"]), ts_end=iso(c["t1"]), duration_s=round(c["t1"] - c["t0"], 3),
            src_ip=c["src"], src_port=c["sport"], dst_ip=c["dst"], dst_port=c["dport"],
            protocol=c["proto"], packets=c["pkts"], bytes_src_to_dst=c["bytes_out"],
            bytes_dst_to_src=c["bytes_in"], tcp_state=state,
            from_infected="yes" if c["src"] in infected else "",
            wireshark_filter=filt))
    hdr = list(rows[0].keys()) if rows else ["conn_id"]
    write_csv(os.path.join(a.out, "network_connections.csv"), rows, hdr)

    print("[4/7] Top destinations của máy nhiễm")
    agg = defaultdict(lambda: dict(conns=0, pkts=0, bytes_out=0, bytes_in=0, ports=set(), first="", last="", s0=0))
    for r in rows:
        if infected and r["src_ip"] not in infected:
            continue
        k = (r["dst_ip"], r["protocol"])
        g = agg[k]
        g["conns"] += 1; g["pkts"] += r["packets"]
        g["bytes_out"] += r["bytes_src_to_dst"]; g["bytes_in"] += r["bytes_dst_to_src"]
        g["ports"].add(r["dst_port"]); g["s0"] += r["tcp_state"] in ("S0-no-reply", "REJ")
        g["first"] = g["first"] or r["ts_start"]; g["last"] = r["ts_start"]
    top = [dict(dst_ip=k[0], protocol=k[1], connections=g["conns"], failed_tcp=g["s0"],
                packets=g["pkts"], bytes_out=g["bytes_out"], bytes_in=g["bytes_in"],
                dst_ports=" ".join(sorted(g["ports"], key=lambda x: int(x or 0))[:15]),
                first_seen=g["first"], last_seen=g["last"]) for k, g in agg.items()]
    top.sort(key=lambda x: -x["connections"])
    write_csv(os.path.join(a.out, "top_destinations.csv"), top,
              list(top[0].keys()) if top else ["dst_ip"])

    print("[5/7] DNS")
    resp = {}
    for p in fields(a.pcap, "dns.flags.response == 1",
                    ["frame.number", "dns.id", "dns.qry.name", "dns.flags.rcode", "dns.a", "dns.cname", "ip.dst"]):
        resp[(p["dns.id"], p["dns.qry.name"].lower(), p["ip.dst"])] = p
    qcount = Counter()
    dns_rows = []
    for p in fields(a.pcap, "dns.flags.response == 0",
                    ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "dns.id", "dns.qry.name", "dns.qry.type"]):
        q = p["dns.qry.name"].lower()
        qcount[q] += 1
        r = resp.get((p["dns.id"], q, p["ip.src"]), {})
        rcode = r.get("dns.flags.rcode", "")
        label = q.split(".")[0] if q else ""
        notes = []
        if rcode == "3": notes.append("NXDOMAIN")
        if rcode and rcode not in ("0", "3"): notes.append(f"rcode={rcode}")
        if not r: notes.append("no-response")
        if len(q) > 50: notes.append("long-name")
        if entropy(label) > 3.5 and len(label) >= 10: notes.append("high-entropy-label")
        dns_rows.append(dict(
            finding_id="", pcap=pcap_name, query_frame=p["frame.number"], response_frame=r.get("frame.number", ""),
            timestamp=iso(p["frame.time_epoch"]), src_ip=p["ip.src"], dns_server=p["ip.dst"],
            query=q, qtype=p["dns.qry.type"], rcode=rcode, answers_A=r.get("dns.a", ""),
            cname=r.get("dns.cname", ""), label_entropy=abs(round(entropy(label), 2)), notes=";".join(notes)))
    for d in dns_rows:
        d["query_count_total"] = qcount[d["query"]]
    hdr = ["finding_id", "pcap", "query_frame", "response_frame", "timestamp", "src_ip", "dns_server",
           "query", "qtype", "rcode", "answers_A", "cname", "query_count_total", "label_entropy", "notes"]
    write_csv(os.path.join(a.out, "dns_findings.csv"), dns_rows, hdr)

    print("[6/7] HTTP")
    http_resp = {}
    for p in fields(a.pcap, "http.response", ["frame.number", "http.request_in", "http.response.code",
                                              "http.content_type", "http.content_length", "http.server"]):
        http_resp[p["http.request_in"]] = p  # khóa = frame của request tương ứng
    http_rows = []
    for p in fields(a.pcap, "http.request", ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst",
                                             "tcp.dstport", "http.request.method", "http.host", "http.request.uri",
                                             "http.user_agent", "http.response_in", "http.content_length"]):
        r = http_resp.get(p["frame.number"], {})
        http_rows.append(dict(
            pcap=pcap_name, frame=p["frame.number"], timestamp=iso(p["frame.time_epoch"]),
            tcp_stream=p["tcp.stream"], src_ip=p["ip.src"], dst_ip=p["ip.dst"], dst_port=p["tcp.dstport"],
            method=p["http.request.method"], host=p["http.host"], uri=p["http.request.uri"][:300],
            user_agent=p["http.user_agent"], req_body_len=p["http.content_length"],
            response_frame=r.get("frame.number", ""), status=r.get("http.response.code", ""),
            content_type=r.get("http.content_type", ""), resp_len=r.get("http.content_length", "")))
    write_csv(os.path.join(a.out, "http_requests.csv"), http_rows,
              list(http_rows[0].keys()) if http_rows else ["frame"])

    print("[7/7] IRC / SMTP (dấu hiệu C2 IRC và spam)")
    misc = []
    for p in fields(a.pcap, "irc.request or irc.response",
                    ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "tcp.dstport",
                     "irc.request.command", "irc.request", "irc.response"]):
        misc.append(dict(proto="IRC", frame=p["frame.number"], timestamp=iso(p["frame.time_epoch"]),
                         tcp_stream=p["tcp.stream"], src_ip=p["ip.src"], dst_ip=p["ip.dst"],
                         dst_port=p["tcp.dstport"], command=p["irc.request.command"],
                         detail=(p["irc.request"] or p["irc.response"])[:200]))
    for p in fields(a.pcap, "smtp.req.command",
                    ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "tcp.dstport",
                     "smtp.req.command", "smtp.req.parameter"]):
        misc.append(dict(proto="SMTP", frame=p["frame.number"], timestamp=iso(p["frame.time_epoch"]),
                         tcp_stream=p["tcp.stream"], src_ip=p["ip.src"], dst_ip=p["ip.dst"],
                         dst_port=p["tcp.dstport"], command=p["smtp.req.command"],
                         detail=p["smtp.req.parameter"][:200]))
    write_csv(os.path.join(a.out, "irc_smtp_activity.csv"), misc,
              ["proto", "frame", "timestamp", "tcp_stream", "src_ip", "dst_ip", "dst_port", "command", "detail"])
    print("Xong. Mở top_destinations.csv và dns_findings.csv trước để chọn candidate.")

if __name__ == "__main__":
    main()
