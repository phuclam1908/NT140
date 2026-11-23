#!/usr/bin/env python3
"""
forensics_extract.py — Network Forensics (Thương) — NT140

Trích xuất bằng chứng mạng từ 1 PCAP bằng TShark/capinfos (chỉ đọc, không export
object ra đĩa) và sinh các file bàn giao trong thư mục --out:

  metadata.txt                 capinfos (TZ=UTC) + SHA-256 + mốc UTC + cảnh báo
  protocol_hierarchy.txt       tshark -qz io,phs
  conversations_{ip,tcp,udp}.txt, endpoints_ip.txt
  network_connections.csv      1 dòng / TCP stream hoặc UDP stream (đơn vị: stream)
  top_destinations.csv         gộp stream do máy nhiễm khởi tạo theo IP đích
  dns_findings.csv             gộp theo query name (đã khử query trùng do capture)
  dns_queries_full.csv.gz      chi tiết từng query (gzip tất định, mtime=0)
  dns_orphan_responses.csv     response không ghép được với query nào
  http_requests.csv            mỗi HTTP request 1 dòng (query string dài đã che); cột detection =
                               dissector (TShark mặc định nhận) / payload_heuristic (chỉ nhận khi ép
                               decode-as HTTP trên port phi chuẩn), wireshark_label = nhãn mặc định
  http_pe_responses.csv        response có body bắt đầu 'MZ' / octet-stream: prefix hex + SHA-256 tính trong bộ nhớ
  sn_php_requests.csv          tập con http_requests có path kết thúc /sn.php
  dns_to_connection.csv        HTTP Host -> DNS query/answer -> kết nối
  irc_smtp_activity.csv        lệnh/response SMTP + IRC (đã che email, không ghi AUTH payload)
  wireshark_zeek_crosscheck.csv  (chỉ khi có --zeek-dir)

Yêu cầu: Wireshark/TShark >= 3.6 (đã kiểm thử 4.6.9), Python >= 3.8.
Ví dụ:
  python scripts/forensics_extract.py datasets/scenario-01-neris/pcap/botnet-capture-20110810-neris.pcap \
      --scenario S01 --infected 147.32.84.165 --out analysis/network-forensics/S01
Nếu bỏ trống đường dẫn PCAP, script thử lần lượt:
  data/raw/scenario-01-neris/pcap/<file>   (chuẩn README nhóm)
  datasets/scenario-01-neris/pcap/<file>   (vị trí hiện tại trên máy Thương)
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

LOG = logging.getLogger("forensics_extract")

DEFAULT_PCAP_NAME = "botnet-capture-20110810-neris.pcap"
DEFAULT_PCAP_CANDIDATES = (
    os.path.join("data", "raw", "scenario-01-neris", "pcap", DEFAULT_PCAP_NAME),
    os.path.join("datasets", "scenario-01-neris", "pcap", DEFAULT_PCAP_NAME),
)
WINDOWS_WIRESHARK_DIR = r"C:\Program Files\Wireshark"
DUP_WINDOW_S = Decimal("0.001")          # gói giống hệt cách nhau < 1 ms => nghi trùng do capture
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
US = Decimal("0.000001")

# Dòng stderr vô hại cần bỏ qua
STDERR_IGNORE = (
    re.compile(r'Running as user "root"', re.I),
    re.compile(r"^\s*$"),
)
CUT_SHORT_RE = re.compile(r"appears to have been cut short", re.I)

DNS_QTYPES = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX",
              "16": "TXT", "28": "AAAA", "33": "SRV", "255": "ANY"}
DNS_RCODES = {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN",
              "4": "NOTIMP", "5": "REFUSED"}


# --------------------------------------------------------------------------- lỗi
class ToolError(RuntimeError):
    """Lỗi khi gọi TShark/capinfos (không tìm thấy, returncode != 0, timeout...)."""


class FieldMissingError(ToolError):
    """Field TShark không tồn tại trong phiên bản đang dùng."""


# ------------------------------------------------------------------- hàm thuần
TRUE_VALUES = {"1", "true", "yes"}


def flag_on(value) -> bool:
    """Đọc cờ TShark ổn định: '1'/'0', 'True'/'False', có thể có nhiều giá trị nối bằng '|'."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return any(part.strip().lower() in TRUE_VALUES for part in str(value).split("|"))


def _dec(value) -> Decimal | None:
    try:
        return Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None


def iso_utc(epoch) -> str:
    """Epoch (chuỗi TShark, tối đa 9 chữ số lẻ) -> 'YYYY-MM-DDTHH:MM:SS.ffffffZ' (UTC, microsecond).

    Dùng Decimal để không mất chính xác do float; làm tròn half-even tới microsecond.
    """
    d = _dec(epoch)
    if d is None or epoch == "":
        return ""
    micros = int((d.quantize(US, rounding=ROUND_HALF_EVEN) * 1_000_000).to_integral_value())
    return (EPOCH + timedelta(microseconds=micros)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def rel6(value) -> str:
    """frame.time_relative -> chuỗi 6 chữ số thập phân."""
    d = _dec(value)
    if d is None or value == "":
        return ""
    return f"{d.quantize(US, rounding=ROUND_HALF_EVEN):.6f}"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def mask_email(text: str) -> str:
    """Che local-part của mọi địa chỉ email: 'john.doe@example.com' -> 'j***@example.com'."""
    if not text:
        return text
    return EMAIL_RE.sub(lambda m: f"{m.group(1)[0]}***@{m.group(2)}", text)


def mask_token(value: str, keep: int = 4) -> str:
    """Che giá trị định danh (bot ID...) sau `keep` ký tự, giữ độ dài để đối chiếu."""
    if not value or len(value) <= keep:
        return value
    return f"{value[:keep]}...[len={len(value)}]"


def mask_uri(uri: str, min_len: int = 16, keep: int = 4) -> str:
    """Che các giá trị query string dài (>= min_len), ví dụ /sn.php?c=<hex> hoặc /?<hex>."""
    if not uri or "?" not in uri:
        return uri
    path, query = uri.split("?", 1)
    parts = []
    for item in query.split("&"):
        if "=" in item:
            k, v = item.split("=", 1)
            parts.append(f"{k}={mask_token(v, keep) if len(v) >= min_len else v}")
        else:
            parts.append(mask_token(item, keep) if len(item) >= min_len else item)
    return f"{path}?{'&'.join(parts)}"


def redact_smtp(command: str, parameter: str) -> str:
    """Tham số SMTP an toàn để ghi.

    AUTH: chỉ giữ cơ chế (không ghi initial-response). EHLO/HELO: tên host bot tự đặt có thể
    suy ra từ tên tài khoản -> che sau 3 ký tự. Còn lại (MAIL/RCPT...): che local-part email.
    """
    cmd = (command or "").upper()
    param = parameter or ""
    if cmd == "AUTH":
        return param.split()[0].upper() + (" [initial-response-redacted]" if len(param.split()) > 1 else "") if param else ""
    if cmd in ("EHLO", "HELO"):
        return mask_token(param, 3)
    return mask_email(param)


def redact_smtp_response(code: str, text: str) -> str:
    """Response SMTP: 334 (challenge base64 của AUTH) không ghi; còn lại che email."""
    if "334" in (code or "").split("|"):
        return "[auth-challenge-redacted]"
    return mask_email(text or "")


def dup_key(pkt: dict) -> tuple:
    """Khoá nhận diện gói trùng do capture: cùng ip.id, ip.src, ip.dst, tcp.seq, tcp.len (UDP: port + udp.length)."""
    if pkt.get("tcp.stream", "") != "":
        return ("T", pkt.get("ip.id", ""), pkt.get("ip.src", ""), pkt.get("ip.dst", ""),
                pkt.get("tcp.srcport", ""), pkt.get("tcp.dstport", ""),
                pkt.get("tcp.seq_raw", ""), pkt.get("tcp.len", ""), pkt.get("tcp.flags", ""))
    return ("U", pkt.get("ip.id", ""), pkt.get("ip.src", ""), pkt.get("ip.dst", ""),
            pkt.get("udp.srcport", ""), pkt.get("udp.dstport", ""), pkt.get("udp.length", ""))


class DupDetector:
    """Đánh dấu gói giống hệt gói trước đó (cùng dup_key) xuất hiện trong < 1 ms."""

    def __init__(self, window: Decimal = DUP_WINDOW_S):
        self.window = window
        self.last: dict[tuple, Decimal] = {}

    def is_dup(self, key: tuple, t: Decimal) -> bool:
        prev = self.last.get(key)
        self.last[key] = t
        return prev is not None and Decimal(0) <= t - prev < self.window


def classify_tcp(pkts: list[dict]) -> dict:
    """Phân loại trạng thái TCP stream.

    pkts: danh sách gói theo thứ tự frame, mỗi gói có src, dst, syn, ack, fin, rst (bool).
    - initiator = nguồn của gói SYN (không ACK) ĐẦU TIÊN; không có SYN -> PARTIAL, initiator = gói đầu (giả định).
    - S0: có SYN, bên đáp không gửi gói nào.
    - REJ: có SYN, bên đáp gửi RST, chưa hoàn tất bắt tay.
    - EST_FIN / EST_RST / EST_OPEN: bắt tay đủ (SYN, SYN-ACK từ bên đáp, rồi ACK từ bên khởi tạo);
      kết thúc theo sự kiện kết thúc CUỐI CÙNG (FIN hay RST); không thấy kết thúc -> EST_OPEN.
    - SYN_ACK_NO_ACK: có SYN-ACK nhưng không thấy ACK hoàn tất (half-open).
    - PARTIAL: không thấy SYN khởi tạo, hoặc trường hợp khác.
    """
    res = dict(initiator="", responder="", initiator_assumed=False, state="PARTIAL",
               syn_count=0, synack_count=0, rst_by="", fin_by="")
    if not pkts:
        return res
    first_syn = next((p for p in pkts if p["syn"] and not p["ack"]), None)
    if first_syn is None:
        orig, resp = pkts[0]["src"], pkts[0]["dst"]
        res["initiator_assumed"] = True
    else:
        orig, resp = first_syn["src"], first_syn["dst"]
    res["initiator"], res["responder"] = orig, resp

    rst_sides, fin_sides = [], []
    handshake = False
    synack_seen = False
    resp_pkts = 0
    last_term = ""
    for p in pkts:
        side = "orig" if p["src"] == orig else "resp"
        if side == "resp":
            resp_pkts += 1
        if p["syn"] and not p["ack"] and side == "orig":
            res["syn_count"] += 1
        if p["syn"] and p["ack"] and side == "resp":
            res["synack_count"] += 1
            synack_seen = True
        if synack_seen and side == "orig" and p["ack"] and not p["syn"] and not p["rst"]:
            handshake = True
        if p["rst"]:
            if side not in rst_sides:
                rst_sides.append(side)
            last_term = "RST"
        if p["fin"]:
            if side not in fin_sides:
                fin_sides.append(side)
            if last_term != "RST":
                last_term = "FIN"
    res["rst_by"] = "/".join(rst_sides)
    res["fin_by"] = "/".join(fin_sides)

    if first_syn is None:
        res["state"] = "PARTIAL"
    elif handshake:
        res["state"] = {"RST": "EST_RST", "FIN": "EST_FIN"}.get(last_term, "EST_OPEN")
    elif "resp" in rst_sides:
        res["state"] = "REJ"
    elif resp_pkts == 0:
        res["state"] = "S0"
    elif synack_seen:
        res["state"] = "SYN_ACK_NO_ACK"
    else:
        res["state"] = "PARTIAL"
    return res


def split_dns_answers(count_answers, resp_types, resp_names, a_values, cname_values):
    """Tách bản ghi answer section khỏi authority/additional.

    TShark trả các RR theo thứ tự xuất hiện (answer -> authority -> additional) trong
    dns.resp.type / dns.resp.name; dns.a và dns.cname chỉ chứa giá trị của RR loại tương ứng
    nên phải tiêu thụ tuần tự theo resp.type. Trả về (answer_A, answer_CNAME, other_A).
    """
    def lst(v):
        if isinstance(v, (list, tuple)):
            return list(v)
        return [x for x in str(v or "").split("|") if x != ""]

    try:
        n_ans = int(str(count_answers or "0").split("|")[0])
    except ValueError:
        n_ans = 0
    types = lst(resp_types)  # resp_names giữ trong chữ ký để đối chiếu thủ công, không cần cho việc tách
    a_iter, c_iter = iter(lst(a_values)), iter(lst(cname_values))
    ans_a, ans_c, other_a = [], [], []
    for i, t in enumerate(types):
        if t == "1":
            ip = next(a_iter, "")
            (ans_a if i < n_ans else other_a).append(ip)
        elif t == "5":
            cn = next(c_iter, "")
            if i < n_ans:
                ans_c.append(cn)
    return ans_a, ans_c, other_a


def match_dns(queries: list[dict], responses: list[dict], have_response_to: bool):
    """Ghép DNS response -> query.

    Khoá chính: dns.response_to của response (frame query). Fallback (khi TShark không có
    field): (dns.id, qname, 5-tuple đảo chiều) với query gần nhất trước response.
    Trả về (map query_frame -> response, danh sách orphan responses).
    """
    by_frame = {q["frame"]: q for q in queries}
    alias = {}
    for q in queries:
        for d in q.get("dup_frames", []):
            alias[d] = q["frame"]
    matched: dict[str, dict] = {}
    orphans = []
    index = defaultdict(list)
    if not have_response_to:
        for q in queries:
            index[(q["dns_id"], q["qname"], q["src_ip"], q["src_port"], q["dst_ip"], q["dst_port"])].append(q)
    for r in responses:
        qf = ""
        if have_response_to and r.get("response_to"):
            qf = alias.get(r["response_to"], r["response_to"])
            if qf not in by_frame:
                qf = ""
        elif not have_response_to:
            cands = index.get((r["dns_id"], r["qname"], r["dst_ip"], r["dst_port"], r["src_ip"], r["src_port"]), [])
            cands = [q for q in cands if q["t"] <= r["t"] and q["frame"] not in matched]
            if cands:
                qf = cands[-1]["frame"]
        if qf and qf not in matched:
            matched[qf] = r
        else:
            orphans.append(r)
    return matched, orphans


def parse_zeek_conn(path: str) -> list[dict]:
    """Đọc Zeek conn.log (JSON-lines hoặc ASCII TSV có dòng #fields)."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        first = f.readline()
        f.seek(0)
        if first.lstrip().startswith("{"):
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
        else:
            fields_ = []
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields_ = line.split("\t")[1:]
                elif line and not line.startswith("#"):
                    rows.append(dict(zip(fields_, line.split("\t"))))
    out = []
    for r in rows:
        try:
            out.append(dict(uid=r.get("uid", ""), ts=float(r.get("ts")), proto=str(r.get("proto", "")).upper(),
                            orig_h=r.get("id.orig_h", ""), orig_p=str(r.get("id.orig_p", "")),
                            resp_h=r.get("id.resp_h", ""), resp_p=str(r.get("id.resp_p", "")),
                            conn_state=r.get("conn_state", ""), history=r.get("history", "")))
        except (TypeError, ValueError):
            continue
    return out


def crosscheck_zeek(conn_rows: list[dict], zeek: list[dict], tol: float = 1.0) -> list[dict]:
    """Ghép stream TShark với Zeek conn theo 5-tuple + |ts_start| <= tol; đếm Zeek conn nằm trong khoảng stream."""
    idx = defaultdict(list)
    for z in zeek:
        idx[(z["proto"], z["orig_h"], z["orig_p"], z["resp_h"], z["resp_p"])].append(z)
    out = []
    for c in conn_rows:
        key = (c["protocol"], c["src_ip"], c["src_port"], c["dst_ip"], c["dst_port"])
        t0, t1 = float(c["_t0"]), float(c["_t1"])
        cands = idx.get(key, [])
        start = [z for z in cands if abs(z["ts"] - t0) <= tol]
        within = [z for z in cands if t0 - tol <= z["ts"] <= t1 + tol]
        out.append(dict(conn_id=c["conn_id"], protocol=c["protocol"], stream=c["stream"],
                        ts_start_utc=c["ts_start_utc"], src_ip=c["src_ip"], src_port=c["src_port"],
                        dst_ip=c["dst_ip"], dst_port=c["dst_port"], tcp_state=c["tcp_state"],
                        zeek_start_match_uid=";".join(z["uid"] for z in start),
                        zeek_conns_in_stream_span=len(within),
                        zeek_conn_states=";".join(z["conn_state"] for z in within),
                        zeek_histories=";".join(z["history"] for z in within),
                        match_type=("none" if not within else "1:1" if len(within) == 1 else f"1:{len(within)}")))
    return out


# ------------------------------------------------------------------ gọi TShark
class Tshark:
    def __init__(self, tshark: str, capinfos: str | None, timeout: int = 1800):
        self.bin = tshark
        self.capinfos = capinfos
        self.timeout = timeout
        self.version = self._version()
        self._fields: set[str] | None = None
        self.warnings: list[str] = []

    def _exec(self, cmd: list[str], env=None, what="tshark") -> str:
        LOG.debug("RUN %s", " ".join(cmd))
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=self.timeout, env=env)
        except FileNotFoundError as e:
            raise ToolError(f"Không chạy được {what}: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise ToolError(f"{what} quá thời gian {self.timeout}s: {' '.join(cmd)}") from e
        err_lines = [l for l in (p.stderr or "").splitlines()
                     if not any(rx.search(l) for rx in STDERR_IGNORE)]
        for l in err_lines:
            if CUT_SHORT_RE.search(l):
                msg = f"{what}: {l.strip()}"
                if msg not in self.warnings:
                    self.warnings.append(msg)
                    LOG.warning("PCAP có thể bị cắt cụt: %s", l.strip())
        fatal = [l for l in err_lines if not CUT_SHORT_RE.search(l)]
        if p.returncode != 0:
            # TShark trả 2 khi file bị cắt cụt nhưng vẫn in được dữ liệu -> chỉ cảnh báo
            if p.returncode == 2 and not fatal and self.warnings:
                return p.stdout
            raise ToolError(f"{what} lỗi (returncode={p.returncode}): {' | '.join(fatal) or '(không có stderr)'}\n"
                            f"Lệnh: {' '.join(cmd)}")
        for l in fatal:
            LOG.warning("%s stderr: %s", what, l)
        return p.stdout

    def _version(self) -> str:
        out = self._exec([self.bin, "--version"])
        return out.splitlines()[0].strip() if out else "unknown"

    def capinfos_version(self) -> str:
        if not self.capinfos:
            return "(không có capinfos)"
        try:
            return self._exec([self.capinfos, "--version"], what="capinfos").splitlines()[0].strip()
        except ToolError as e:
            return f"(lỗi: {e})"

    def available_fields(self) -> set[str]:
        if self._fields is None:
            out = self._exec([self.bin, "-G", "fields"])
            self._fields = {l.split("\t")[2] for l in out.splitlines() if l.startswith("F\t") and l.count("\t") >= 2}
        return self._fields

    def require(self, flds: list[str]) -> None:
        missing = [f for f in flds if f not in self.available_fields()]
        if missing:
            raise FieldMissingError(f"Field TShark không tồn tại: {', '.join(missing)} (phiên bản: {self.version})")

    def has(self, f: str) -> bool:
        return f in self.available_fields()

    def run(self, args: list[str]) -> str:
        return self._exec([self.bin] + args)

    def fields(self, pcap: str, display_filter: str, flds: list[str], extra: list[str] | None = None):
        self.require(flds)
        args = ["-r", pcap, "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
                "-E", "aggregator=|", "-E", "quote=n"] + (extra or [])
        if display_filter:
            args += ["-Y", display_filter]
        for f in flds:
            args += ["-e", f]
        out = self.run(args)
        for line in out.splitlines():
            parts = line.split("\t")
            parts += [""] * (len(flds) - len(parts))
            yield dict(zip(flds, parts))

    def capinfos_report(self, pcap: str) -> str:
        if not self.capinfos:
            msg = "capinfos không tìm thấy — bỏ qua metadata chi tiết"
            LOG.warning(msg)
            self.warnings.append(msg)
            return "(không tìm thấy capinfos)\n"
        env = dict(os.environ, TZ="UTC")   # capinfos in giờ theo TZ; ép UTC
        try:
            return self._exec([self.capinfos, "-M", pcap], env=env, what="capinfos")
        except ToolError as e:
            LOG.warning("capinfos thất bại, vẫn tiếp tục: %s", e)
            self.warnings.append(f"capinfos thất bại: {e}")
            return f"(capinfos lỗi: {e})\n"


def find_tool(name: str, env_var: str, explicit: str | None = None) -> str | None:
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get(env_var):
        cands.append(os.environ[env_var])
    w = shutil.which(name)
    if w:
        cands.append(w)
    cands += [os.path.join(WINDOWS_WIRESHARK_DIR, name + ".exe"), os.path.join("/usr/bin", name)]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def resolve_pcap(arg: str | None) -> str:
    cands = [arg] if arg else list(DEFAULT_PCAP_CANDIDATES)
    for c in cands:
        if c and os.path.isfile(c):
            return c
    raise FileNotFoundError("Không tìm thấy PCAP. Đã thử: " + ", ".join(cands))


def check_pcap(path: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"PCAP không tồn tại: {path}")
    if os.path.getsize(path) == 0:
        raise ValueError(f"PCAP rỗng (0 byte): {path}")
    with open(path, "rb") as f:
        if len(f.read(24)) < 24:
            raise ValueError(f"PCAP quá ngắn, không đủ global header: {path}")


# ------------------------------------------------------------------- ghi file
def write_csv(path: str, rows: list[dict], header: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    LOG.info("  -> %s (%d dòng)", path, len(rows))


def write_csv_gz(path: str, rows: list[dict], header: list[str]) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=header, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            gz.write(buf.getvalue().encode("utf-8"))
    LOG.info("  -> %s (%d dòng, gzip)", path, len(rows))


# --------------------------------------------------------------------- các bước
def step_metadata(ts: Tshark, pcap: str, out: str, pcap_name: str) -> dict:
    LOG.info("[1/8] Metadata + SHA-256")
    digest = sha256_file(pcap)
    cap = ts.capinfos_report(pcap)
    cap = cap.replace(pcap, pcap_name).replace(pcap.replace("\\", "/"), pcap_name)
    first = last = None
    n = 0
    for p in ts.fields(pcap, "", ["frame.time_epoch"]):
        n += 1
        t = _dec(p["frame.time_epoch"])
        if t is None:
            continue
        first = t if first is None or t < first else first
        last = t if last is None or t > last else last
    info = dict(sha256=digest, packets=n, first=first, last=last)
    with open(os.path.join(out, "metadata.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"PCAP: {pcap_name}\nSHA-256: {digest}\nSize (bytes): {os.path.getsize(pcap)}\n")
        f.write(f"Packets (tshark frames): {n}\n")
        if first is not None:
            f.write(f"First packet (UTC): {iso_utc(first)}\nLast packet (UTC):  {iso_utc(last)}\n"
                    f"Duration (s): {rel6(last - first)}\n")
        f.write(f"TShark: {ts.version}\nCapinfos: {ts.capinfos_version()}\n")
        f.write("Warnings: " + ("; ".join(ts.warnings) if ts.warnings else "none") + "\n")
        f.write("\n# capinfos -M (chạy với TZ=UTC, các mốc thời gian bên dưới là UTC)\n")
        f.write(cap)
    return info


def step_stats(ts: Tshark, pcap: str, out: str) -> None:
    LOG.info("[2/8] Protocol hierarchy + conversations")
    for name, z in [("protocol_hierarchy.txt", "io,phs"), ("conversations_ip.txt", "conv,ip"),
                    ("conversations_tcp.txt", "conv,tcp"), ("conversations_udp.txt", "conv,udp"),
                    ("endpoints_ip.txt", "endpoints,ip")]:
        txt = ts.run(["-r", pcap, "-n", "-q", "-z", z])
        with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(txt.replace(pcap, os.path.basename(pcap)))


CONN_FIELDS = ["frame.number", "frame.time_epoch", "frame.time_relative", "frame.len", "ip.src", "ip.dst",
               "ip.id", "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack",
               "tcp.flags.reset", "tcp.flags.fin", "tcp.seq_raw", "tcp.len", "tcp.flags",
               "tcp.analysis.retransmission", "udp.stream", "udp.srcport", "udp.dstport", "udp.length"]


def build_connections(packets, sid: str, pcap_name: str, infected: set[str]):
    """packets: iterable dict theo CONN_FIELDS. Trả về (rows, dup_stats)."""
    streams: "OrderedDict[tuple, dict]" = OrderedDict()
    dd = DupDetector()
    dup_total = Counter()
    for p in packets:
        if p.get("tcp.stream", "") != "":
            key = ("TCP", p["tcp.stream"])
        elif p.get("udp.stream", "") != "":
            key = ("UDP", p["udp.stream"])
        else:
            continue
        t = _dec(p["frame.time_epoch"]) or Decimal(0)
        is_dup = dd.is_dup(dup_key(p), t)
        s = streams.get(key)
        if s is None:
            s = streams[key] = dict(proto=key[0], stream=key[1], pkts=[], first_frame=p["frame.number"],
                                    t0=p["frame.time_epoch"], r0=p["frame.time_relative"], retrans=0, dups=0)
        s["last_frame"], s["t1"], s["r1"] = p["frame.number"], p["frame.time_epoch"], p["frame.time_relative"]
        s["pkts"].append(dict(src=p["ip.src"], dst=p["ip.dst"], len=int(p.get("frame.len") or 0),
                              sport=p.get("tcp.srcport") or p.get("udp.srcport", ""),
                              dport=p.get("tcp.dstport") or p.get("udp.dstport", ""),
                              syn=flag_on(p.get("tcp.flags.syn")), ack=flag_on(p.get("tcp.flags.ack")),
                              fin=flag_on(p.get("tcp.flags.fin")), rst=flag_on(p.get("tcp.flags.reset")),
                              dup=is_dup))
        if p.get("tcp.analysis.retransmission", "") != "":
            s["retrans"] += 1
        if is_dup:
            s["dups"] += 1
            dup_total[key[0]] += 1
    rows = []
    for s in sorted(streams.values(), key=lambda x: int(x["first_frame"])):
        pk = s["pkts"]
        if s["proto"] == "TCP":
            cl = classify_tcp(pk)
            orig = cl["initiator"]
            ref = next((x for x in pk if x["src"] == orig), pk[0])
            filt = f"tcp.stream eq {s['stream']}"
        else:
            cl = dict(state="-", initiator_assumed=True, syn_count="", synack_count="", rst_by="", fin_by="")
            orig = pk[0]["src"]
            ref = pk[0]
            filt = f"udp.stream eq {s['stream']}"
        out_b = sum(x["len"] for x in pk if x["src"] == orig)
        in_b = sum(x["len"] for x in pk if x["src"] != orig)
        dur = (_dec(s["t1"]) or 0) - (_dec(s["t0"]) or 0)
        rows.append(dict(
            conn_id=f"{sid}-{s['proto']}{s['stream']}", pcap=pcap_name, protocol=s["proto"], stream=s["stream"],
            first_frame=s["first_frame"], last_frame=s["last_frame"],
            ts_utc=iso_utc(s["t0"]), rel_time=rel6(s["r0"]),
            ts_start_utc=iso_utc(s["t0"]), rel_start=rel6(s["r0"]),
            ts_end_utc=iso_utc(s["t1"]), rel_end=rel6(s["r1"]), duration_s=rel6(dur),
            src_ip=orig, src_port=ref["sport"] if ref["src"] == orig else ref["dport"],
            dst_ip=ref["dst"] if ref["src"] == orig else ref["src"],
            dst_port=ref["dport"] if ref["src"] == orig else ref["sport"],
            packets=len(pk), packets_dedup=len(pk) - s["dups"],
            bytes_src_to_dst=out_b, bytes_dst_to_src=in_b,
            tcp_state=cl["state"], initiator_assumed="yes" if cl["initiator_assumed"] else "",
            syn_count=cl["syn_count"], synack_count=cl["synack_count"], rst_by=cl["rst_by"], fin_by=cl["fin_by"],
            retrans_count=s["retrans"] if s["proto"] == "TCP" else "", dup_suspect_count=s["dups"],
            from_infected="yes" if orig in infected else "", wireshark_filter=filt,
            _t0=s["t0"], _t1=s["t1"]))
    return rows, dup_total


CONN_HEADER = ["conn_id", "pcap", "protocol", "stream", "first_frame", "last_frame", "ts_utc", "rel_time",
               "ts_start_utc", "rel_start", "ts_end_utc", "rel_end", "duration_s", "src_ip", "src_port",
               "dst_ip", "dst_port", "packets", "packets_dedup", "bytes_src_to_dst", "bytes_dst_to_src",
               "tcp_state", "initiator_assumed", "syn_count", "synack_count", "rst_by", "fin_by",
               "retrans_count", "dup_suspect_count", "from_infected", "wireshark_filter"]


def top_destinations(rows: list[dict], infected: set[str]) -> list[dict]:
    agg = {}
    for r in rows:
        if infected and r["src_ip"] not in infected:
            continue
        k = (r["dst_ip"], r["protocol"])
        g = agg.setdefault(k, dict(streams=0, failed=0, pkts=0, pkts_d=0, b_out=0, b_in=0, ports=Counter(),
                                   first=None, last=None, states=Counter()))
        g["streams"] += 1
        g["pkts"] += r["packets"]
        g["pkts_d"] += r["packets_dedup"]
        g["b_out"] += r["bytes_src_to_dst"]
        g["b_in"] += r["bytes_dst_to_src"]
        g["ports"][r["dst_port"]] += 1
        g["failed"] += r["tcp_state"] in ("S0", "REJ")
        g["states"][r["tcp_state"]] += 1
        g["first"] = g["first"] or r
        g["last"] = r
    top = []
    for (ip, proto), g in agg.items():
        top.append(dict(
            dst_ip=ip, protocol=proto, streams=g["streams"], failed_tcp_s0_rej=g["failed"],
            tcp_states=";".join(f"{k}:{v}" for k, v in sorted(g["states"].items())) if proto == "TCP" else "",
            packets=g["pkts"], packets_dedup=g["pkts_d"], bytes_out=g["b_out"], bytes_in=g["b_in"],
            dst_ports=" ".join(f"{p}({c})" for p, c in sorted(g["ports"].items(), key=lambda x: (-x[1], int(x[0] or 0)))[:15]),
            ts_utc=g["first"]["ts_start_utc"], rel_time=g["first"]["rel_start"],
            last_seen_utc=g["last"]["ts_start_utc"], last_rel_time=g["last"]["rel_start"]))
    top.sort(key=lambda x: (-x["streams"], x["dst_ip"], x["protocol"]))
    return top


DNS_FIELDS = ["frame.number", "frame.time_epoch", "frame.time_relative", "ip.src", "ip.dst", "ip.id",
              "udp.srcport", "udp.dstport", "udp.stream", "tcp.srcport", "tcp.dstport", "dns.id",
              "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.count.answers",
              "dns.resp.type", "dns.resp.name", "dns.a", "dns.cname"]


def build_dns(packets, resolver: str, have_response_to: bool):
    """Trả về (queries đã khử trùng, matched map, orphans, stats)."""
    queries, responses = [], []
    last_q: dict[tuple, dict] = {}
    stats = Counter()
    for p in packets:
        is_resp = flag_on(p["dns.flags.response"])
        base = dict(frame=p["frame.number"], t=_dec(p["frame.time_epoch"]) or Decimal(0),
                    epoch=p["frame.time_epoch"], rel=p["frame.time_relative"],
                    src_ip=p["ip.src"], dst_ip=p["ip.dst"],
                    src_port=p["udp.srcport"] or p["tcp.srcport"], dst_port=p["udp.dstport"] or p["tcp.dstport"],
                    udp_stream=p["udp.stream"], dns_id=p["dns.id"],
                    qname=p["dns.qry.name"].split("|")[0].lower(), qtype=p["dns.qry.type"].split("|")[0])
        if is_resp:
            stats["responses_raw"] += 1
            ans_a, ans_c, other_a = split_dns_answers(p["dns.count.answers"], p["dns.resp.type"],
                                                      p["dns.resp.name"], p["dns.a"], p["dns.cname"])
            base.update(rcode=p["dns.flags.rcode"].split("|")[0], answers_A=ans_a, answers_CNAME=ans_c,
                        other_A=other_a, response_to=p.get("dns.response_to", ""))
            if base["rcode"] == "3":
                stats["nxdomain_responses_raw"] += 1
            responses.append(base)
            continue
        stats["queries_raw"] += 1
        k = (base["dns_id"], base["qname"], base["qtype"], base["src_ip"], base["dst_ip"],
             base["src_port"], base["dst_port"])
        prev = last_q.get(k)
        if prev is not None and Decimal(0) <= base["t"] - prev["_t_last"] < DUP_WINDOW_S:
            prev["dup_frames"].append(base["frame"])
            prev["_t_last"] = base["t"]
            stats["queries_capture_dup"] += 1
            continue
        base.update(dup_frames=[], retrans_of=prev["frame"] if prev is not None else "", _t_last=base["t"])
        if prev is not None:
            stats["queries_retransmission"] += 1
        last_q[k] = base
        queries.append(base)
    matched, orphans = match_dns(queries, responses, have_response_to)
    stats["queries_unique"] = len(queries)
    stats["queries_answered"] = len(matched)
    stats["queries_no_response"] = len(queries) - len(matched)
    stats["orphan_responses"] = len(orphans)
    stats["nxdomain_queries"] = sum(1 for r in matched.values() if r["rcode"] == "3")
    return queries, matched, orphans, stats


def dns_rows(queries, matched, resolver: str, pcap_name: str):
    rows = []
    for q in queries:
        r = matched.get(q["frame"])
        label = q["qname"].split(".")[0] if q["qname"] else ""
        notes = []
        rcode = r["rcode"] if r else ""
        if rcode == "3":
            notes.append("NXDOMAIN")
        elif rcode and rcode != "0":
            notes.append(f"rcode={DNS_RCODES.get(rcode, rcode)}")
        if not r:
            notes.append("no-response")
        if q["retrans_of"]:
            notes.append(f"retransmission-of={q['retrans_of']}")
        if len(q["qname"]) > 50:
            notes.append("long-name")
        ent = entropy(label)
        if ent > 3.5 and len(label) >= 10:
            notes.append("high-entropy-label")
        rows.append(dict(
            ts_utc=iso_utc(q["epoch"]), rel_time=rel6(q["rel"]), pcap=pcap_name, query_frame=q["frame"],
            dup_frames=";".join(q["dup_frames"]), response_frame=r["frame"] if r else "",
            response_rel_time=rel6(r["rel"]) if r else "", udp_stream=q["udp_stream"],
            src_ip=q["src_ip"], src_port=q["src_port"], dns_server=q["dst_ip"],
            resolver_type="internal" if q["dst_ip"] == resolver else "external_direct",
            dns_id=q["dns_id"], query=q["qname"], qtype=DNS_QTYPES.get(q["qtype"], q["qtype"]),
            rcode=DNS_RCODES.get(rcode, rcode), answers_A=";".join(r["answers_A"]) if r else "",
            answers_CNAME=";".join(r["answers_CNAME"]) if r else "",
            additional_A_count=len(r["other_A"]) if r else "",
            label_entropy=f"{ent:.2f}", notes=";".join(notes)))
    return rows


DNS_FULL_HEADER = ["ts_utc", "rel_time", "pcap", "query_frame", "dup_frames", "response_frame",
                   "response_rel_time", "udp_stream", "src_ip", "src_port", "dns_server", "resolver_type",
                   "dns_id", "query", "qtype", "rcode", "answers_A", "answers_CNAME", "additional_A_count",
                   "label_entropy", "notes"]


def dns_aggregate(rows: list[dict]) -> list[dict]:
    agg = OrderedDict()
    for r in rows:
        g = agg.get(r["query"])
        if g is None:
            g = agg[r["query"]] = dict(first=r, last=r, n=0, qtypes=Counter(), rcodes=Counter(), ips=OrderedDict(),
                                       servers=Counter(), rtypes=Counter(), noresp=0, retrans=0, notes=set())
        g["last"] = r
        g["n"] += 1
        g["qtypes"][r["qtype"]] += 1
        g["rcodes"][r["rcode"] or "no-response"] += 1
        g["servers"][r["dns_server"]] += 1
        g["rtypes"][r["resolver_type"]] += 1
        g["noresp"] += r["rcode"] == ""
        g["retrans"] += "retransmission-of" in r["notes"]
        for ip in filter(None, r["answers_A"].split(";")):
            g["ips"][ip] = None
        for n in ("long-name", "high-entropy-label"):
            if n in r["notes"]:
                g["notes"].add(n)
    out = []
    for q, g in agg.items():
        rt = sorted(g["rtypes"])
        ips = list(g["ips"])
        out.append(dict(
            query=q, query_count=g["n"], retransmissions=g["retrans"],
            qtypes=";".join(f"{k}:{v}" for k, v in sorted(g["qtypes"].items())),
            rcodes=";".join(f"{k}:{v}" for k, v in sorted(g["rcodes"].items())),
            no_response=g["noresp"], answers_A=";".join(ips[:20]) + (f";...(+{len(ips) - 20})" if len(ips) > 20 else ""),
            answers_A_distinct=len(ips), dns_servers=len(g["servers"]),
            resolver_type=rt[0] if len(rt) == 1 else "mixed",
            ts_utc=g["first"]["ts_utc"], rel_time=g["first"]["rel_time"], first_query_frame=g["first"]["query_frame"],
            last_seen_utc=g["last"]["ts_utc"], last_rel_time=g["last"]["rel_time"],
            notes=";".join(sorted(g["notes"]))))
    return out


DNS_AGG_HEADER = ["query", "query_count", "retransmissions", "qtypes", "rcodes", "no_response", "answers_A",
                  "answers_A_distinct", "dns_servers", "resolver_type", "ts_utc", "rel_time", "first_query_frame",
                  "last_seen_utc", "last_rel_time", "notes"]

HTTP_REQ_FIELDS = ["frame.number", "frame.time_epoch", "frame.time_relative", "tcp.stream", "ip.src", "ip.dst",
                   "tcp.srcport", "tcp.dstport", "http.request.method", "http.host", "http.request.uri",
                   "http.user_agent", "http.content_length_header"]
HTTP_RESP_FIELDS = ["frame.number", "frame.time_relative", "tcp.stream", "http.request_in", "http.response.code",
                    "http.content_type", "http.content_length_header", "http.server"]


def http_detection(frame: str, default_frames: set, labels: dict) -> tuple[str, str]:
    """(detection, wireshark_label) cho 1 request.

    dissector         : TShark mặc định (không -d) đã nhận frame là http.request.
    payload_heuristic : chỉ nhận được khi ép `-d tcp.port==N,http` — dòng đầu payload là request line HTTP
                        nhưng TShark mặc định gán giao thức khác theo port (vd. IRC trên 6667, KRB5 trên 88).
    wireshark_label   : cột Protocol TShark mặc định hiển thị cho frame đó (không decode-as).
    """
    det = "dissector" if frame in default_frames else "payload_heuristic"
    return det, labels.get(frame, "")


def http_rows(reqs, resps, pcap_name, infected, default_frames=None, labels=None):
    labels = labels or {}
    by_req = {}
    for r in resps:
        for rf in r["http.request_in"].split("|"):
            if rf:
                by_req.setdefault(rf, r)
    rows = []
    for p in reqs:
        r = by_req.get(p["frame.number"], {})
        uri = p["http.request.uri"].split("|")[0]
        path = uri.split("?", 1)[0]
        det, wlabel = http_detection(p["frame.number"], default_frames if default_frames is not None
                                     else {p["frame.number"]}, labels)
        rows.append(dict(
            ts_utc=iso_utc(p["frame.time_epoch"]), rel_time=rel6(p["frame.time_relative"]), pcap=pcap_name,
            frame=p["frame.number"], tcp_stream=p["tcp.stream"], src_ip=p["ip.src"], src_port=p["tcp.srcport"],
            dst_ip=p["ip.dst"], dst_port=p["tcp.dstport"],
            direction="from_infected" if p["ip.src"] in infected else ("to_infected" if p["ip.dst"] in infected else "other"),
            method=p["http.request.method"].split("|")[0], host=p["http.host"].split("|")[0],
            uri_path=path[:200], uri=mask_uri(uri)[:300], query_len=len(uri.split("?", 1)[1]) if "?" in uri else 0,
            user_agent=p["http.user_agent"].split("|")[0], req_content_length=p["http.content_length_header"],
            response_frame=r.get("frame.number", ""), response_rel_time=rel6(r.get("frame.time_relative", "")),
            status=r.get("http.response.code", ""), content_type=r.get("http.content_type", ""),
            resp_content_length=r.get("http.content_length_header", ""), server=r.get("http.server", ""),
            detection=det, wireshark_label=wlabel))
    return rows


HTTP_HEADER = ["ts_utc", "rel_time", "pcap", "frame", "tcp_stream", "src_ip", "src_port", "dst_ip", "dst_port",
               "direction", "method", "host", "uri_path", "uri", "query_len", "user_agent", "req_content_length",
               "response_frame", "response_rel_time", "status", "content_type", "resp_content_length", "server",
               "detection", "wireshark_label"]


def body_info(hex_body: str) -> dict:
    """Từ http.file_data (hex) -> prefix 16 byte, độ dài quan sát, SHA-256 (tính trong bộ nhớ, không ghi file)."""
    h = re.sub(r"[^0-9a-fA-F]", "", hex_body or "")
    if len(h) % 2:
        h = h[:-1]
    data = bytes.fromhex(h)
    return dict(body_prefix_hex=data[:16].hex(), is_mz=data[:2] == b"MZ", body_bytes_observed=len(data),
                body_sha256=hashlib.sha256(data).hexdigest() if data else "")


def dns_to_connection(http: list[dict], dns_full: list[dict], conns: list[dict]) -> list[dict]:
    """Cho mỗi (HTTP Host, dst_ip) đầu tiên: truy vấn DNS gần nhất trước request và IP trả về."""
    by_name = defaultdict(list)
    for d in dns_full:
        by_name[d["query"]].append(d)
    conn_by_stream = {c["stream"]: c for c in conns if c["protocol"] == "TCP"}
    seen = OrderedDict()
    for h in http:
        if h["direction"] != "from_infected":
            continue
        host = (h["host"] or "").split(":")[0].lower()
        k = (host, h["dst_ip"], h["dst_port"])
        g = seen.get(k)
        if g is None:
            g = seen[k] = dict(first=h, n=0)
        g["n"] += 1
    out = []
    for (host, ip, port), g in seen.items():
        h = g["first"]
        is_ip = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host))
        prior = [d for d in by_name.get(host, []) if Decimal(d["rel_time"]) <= Decimal(h["rel_time"])]
        last = prior[-1] if prior else None
        with_ip = [d for d in prior if ip in d["answers_A"].split(";")]
        dq = with_ip[-1] if with_ip else last
        c = conn_by_stream.get(h["tcp_stream"], {})
        if is_ip:
            status = "host-is-ip-literal"
        elif not by_name.get(host):
            status = "no-dns-query-in-pcap"
        elif dq is None:
            status = "dns-only-after-request"
        elif ip in dq["answers_A"].split(";"):
            status = "resolved-ip-matches"
        else:
            status = "resolved-ip-differs"
        out.append(dict(
            host=host, dst_ip=ip, dst_port=port, http_requests=g["n"],
            dns_query_frame=dq["query_frame"] if dq else "", dns_response_frame=dq["response_frame"] if dq else "",
            dns_ts_utc=dq["ts_utc"] if dq else "", dns_rel_time=dq["rel_time"] if dq else "",
            dns_server=dq["dns_server"] if dq else "", resolver_type=dq["resolver_type"] if dq else "",
            dns_rcode=dq["rcode"] if dq else "", dns_answers_A=dq["answers_A"] if dq else "",
            dns_queries_total=len(by_name.get(host, [])),
            first_http_frame=h["frame"], ts_utc=h["ts_utc"], rel_time=h["rel_time"], tcp_stream=h["tcp_stream"],
            conn_first_frame=c.get("first_frame", ""), conn_tcp_state=c.get("tcp_state", ""),
            dns_to_conn_delay_s=rel6(Decimal(c.get("rel_start") or h["rel_time"]) - Decimal(dq["response_rel_time"]))
            if dq and dq["response_rel_time"] else "",
            status=status))
    return out


DNS2CONN_HEADER = ["host", "dst_ip", "dst_port", "http_requests", "dns_query_frame", "dns_response_frame",
                   "dns_ts_utc", "dns_rel_time", "dns_server", "resolver_type", "dns_rcode", "dns_answers_A",
                   "dns_queries_total", "first_http_frame", "ts_utc", "rel_time", "tcp_stream", "conn_first_frame",
                   "conn_tcp_state", "dns_to_conn_delay_s", "status"]


# --------------------------------------------------------------------------- main
def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Trích xuất bằng chứng mạng từ PCAP bằng TShark (chỉ đọc).")
    ap.add_argument("pcap", nargs="?", default=None,
                    help="Đường dẫn PCAP; bỏ trống để thử data/raw/... rồi datasets/...")
    ap.add_argument("--scenario", default="S01")
    ap.add_argument("--infected", default="", help="IP máy nhiễm, phân cách dấu phẩy")
    ap.add_argument("--out", default="out")
    ap.add_argument("--resolver", default="147.32.80.9", help="IP DNS resolver nội bộ (resolver_type=internal)")
    ap.add_argument("--http-decode-ports", default="6667,88",
                    help="Port TCP ép giải mã HTTP trong bước HTTP (mặc định 6667,88; rỗng để tắt)")
    ap.add_argument("--zeek-dir", default=None, help="Thư mục chứa Zeek conn.log để xuất wireshark_zeek_crosscheck.csv")
    ap.add_argument("--tshark", default=None, help="Đường dẫn tshark (hoặc biến môi trường TSHARK)")
    ap.add_argument("--capinfos", default=None, help="Đường dẫn capinfos (hoặc biến môi trường CAPINFOS)")
    ap.add_argument("--timeout", type=int, default=1800, help="Timeout mỗi lần gọi TShark (giây)")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    a = parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    tshark = find_tool("tshark", "TSHARK", a.tshark)
    if not tshark:
        LOG.error("Không tìm thấy tshark (đã thử --tshark, $TSHARK, PATH, %s). Cài Wireshark/TShark.",
                  WINDOWS_WIRESHARK_DIR)
        return 3
    capinfos = find_tool("capinfos", "CAPINFOS", a.capinfos) or \
        next((p for p in (os.path.join(os.path.dirname(tshark), n) for n in ("capinfos.exe", "capinfos"))
              if os.path.isfile(p)), None)
    try:
        pcap = resolve_pcap(a.pcap)
        check_pcap(pcap)
    except (FileNotFoundError, ValueError, OSError) as e:
        LOG.error("%s", e)
        return 4
    try:
        return run_all(a, pcap, Tshark(tshark, capinfos, a.timeout))
    except FieldMissingError as e:
        LOG.error("%s", e)
        return 5
    except ToolError as e:
        LOG.error("%s", e)
        return 6


def run_all(a, pcap: str, ts: Tshark) -> int:
    LOG.info("TShark: %s | PCAP: %s", ts.version, pcap)
    os.makedirs(a.out, exist_ok=True)
    pcap_name = os.path.basename(pcap)
    infected = {x.strip() for x in a.infected.split(",") if x.strip()}
    sid = a.scenario
    if not infected:
        LOG.warning("Chưa khai báo --infected: top_destinations sẽ gộp mọi nguồn")

    meta = step_metadata(ts, pcap, a.out, pcap_name)
    step_stats(ts, pcap, a.out)

    LOG.info("[3/8] Connection theo TCP/UDP stream")
    if not ts.has("udp.stream"):
        raise FieldMissingError(f"Field udp.stream không có trong {ts.version}; cần TShark >= 1.12")
    conns, dup_by_proto = build_connections(ts.fields(pcap, "ip and (tcp or udp)", CONN_FIELDS),
                                            sid, pcap_name, infected)
    write_csv(os.path.join(a.out, "network_connections.csv"), conns, CONN_HEADER)

    LOG.info("[4/8] Top destinations của máy nhiễm (đơn vị: stream)")
    top = top_destinations(conns, infected)
    write_csv(os.path.join(a.out, "top_destinations.csv"), top, list(top[0].keys()) if top else ["dst_ip"])

    LOG.info("[5/8] DNS")
    have_rt = ts.has("dns.response_to")
    if not have_rt:
        LOG.warning("dns.response_to không có trong %s -> fallback ghép theo (dns.id, qname, 5-tuple đảo)", ts.version)
    dflds = DNS_FIELDS + (["dns.response_to"] if have_rt else [])
    queries, matched, orphans, dstats = build_dns(ts.fields(pcap, "dns && !icmp", dflds), a.resolver, have_rt)
    dfull = dns_rows(queries, matched, a.resolver, pcap_name)
    write_csv_gz(os.path.join(a.out, "dns_queries_full.csv.gz"), dfull, DNS_FULL_HEADER)
    write_csv(os.path.join(a.out, "dns_findings.csv"), dns_aggregate(dfull), DNS_AGG_HEADER)
    write_csv(os.path.join(a.out, "dns_orphan_responses.csv"),
              [dict(ts_utc=iso_utc(r["epoch"]), rel_time=rel6(r["rel"]), response_frame=r["frame"],
                    src_ip=r["src_ip"], dst_ip=r["dst_ip"], dns_id=r["dns_id"], query=r["qname"],
                    rcode=DNS_RCODES.get(r["rcode"], r["rcode"]), response_to=r.get("response_to", ""),
                    answers_A=";".join(r["answers_A"])) for r in orphans],
              ["ts_utc", "rel_time", "response_frame", "src_ip", "dst_ip", "dns_id", "query", "rcode",
               "response_to", "answers_A"])

    LOG.info("[6/8] HTTP (decode-as thêm: %s)", a.http_decode_ports or "không")
    extra = []
    for port in filter(None, (x.strip() for x in a.http_decode_ports.split(","))):
        extra += ["-d", f"tcp.port=={int(port)},http"]
    reqs = list(ts.fields(pcap, "http.request", HTTP_REQ_FIELDS, extra))
    resps = list(ts.fields(pcap, "http.response", HTTP_RESP_FIELDS, extra))
    # Lượt không decode-as: tập request TShark mặc định nhận + nhãn Protocol mặc định của từng frame
    labels = {p["frame.number"]: p["_ws.col.protocol"]
              for p in ts.fields(pcap, "http.request", ["frame.number", "_ws.col.protocol"])}
    default_frames = set(labels)
    missing = [p["frame.number"] for p in reqs if p["frame.number"] not in default_frames]
    if missing:
        for p in ts.fields(pcap, "frame.number in {%s}" % ",".join(missing), ["frame.number", "_ws.col.protocol"]):
            labels[p["frame.number"]] = p["_ws.col.protocol"]
    LOG.info("  HTTP request: %d (dissector mặc định %d + payload_heuristic %d)",
             len(reqs), len(reqs) - len(missing), len(missing))
    http = http_rows(reqs, resps, pcap_name, infected, default_frames, labels)
    write_csv(os.path.join(a.out, "http_requests.csv"), http, HTTP_HEADER)
    write_csv(os.path.join(a.out, "sn_php_requests.csv"),
              [h for h in http if h["uri_path"].lower().endswith("/sn.php")], HTTP_HEADER)
    req_by_frame = {h["frame"]: h for h in http}
    pe_rows = []
    for p in ts.fields(pcap, 'http.response && (http.file_data[0:2] == 4d:5a || http.content_type contains "octet-stream" '
                             '|| http.content_type contains "dosexec")',
                       ["frame.number", "frame.time_epoch", "frame.time_relative", "tcp.stream", "ip.src", "ip.dst",
                        "http.request_in", "http.response.code", "http.content_type", "http.content_length_header",
                        "http.file_data"], extra):
        rq = req_by_frame.get(p["http.request_in"].split("|")[0], {})
        bi = body_info(p["http.file_data"].split("|")[0])
        pe_rows.append(dict(ts_utc=iso_utc(p["frame.time_epoch"]), rel_time=rel6(p["frame.time_relative"]),
                            response_frame=p["frame.number"], request_frame=p["http.request_in"], tcp_stream=p["tcp.stream"],
                            src_ip=p["ip.src"], dst_ip=p["ip.dst"], host=rq.get("host", ""), uri=rq.get("uri", ""),
                            status=p["http.response.code"], content_type=p["http.content_type"],
                            content_length=p["http.content_length_header"], **bi))
    write_csv(os.path.join(a.out, "http_pe_responses.csv"), pe_rows,
              ["ts_utc", "rel_time", "response_frame", "request_frame", "tcp_stream", "src_ip", "dst_ip", "host",
               "uri", "status", "content_type", "content_length", "body_bytes_observed", "body_prefix_hex",
               "is_mz", "body_sha256"])
    write_csv(os.path.join(a.out, "dns_to_connection.csv"), dns_to_connection(http, dfull, conns), DNS2CONN_HEADER)

    LOG.info("[7/8] IRC / SMTP (che email, không ghi AUTH payload)")
    misc = []
    for p in ts.fields(pcap, "irc.request or irc.response",
                       ["frame.number", "frame.time_epoch", "frame.time_relative", "tcp.stream", "ip.src", "ip.dst",
                        "tcp.srcport", "tcp.dstport", "irc.request.command", "irc.request", "irc.response"]):
        detail = (p["irc.request"] or p["irc.response"]).split("|")[0]
        looks_http = bool(re.match(r"^(GET|POST|HEAD|PUT|HTTP/1\.[01])\b", detail))
        misc.append(dict(ts_utc=iso_utc(p["frame.time_epoch"]), rel_time=rel6(p["frame.time_relative"]), proto="IRC",
                         kind="request" if p["irc.request"] else "response", frame=p["frame.number"],
                         tcp_stream=p["tcp.stream"], src_ip=p["ip.src"], src_port=p["tcp.srcport"], dst_ip=p["ip.dst"],
                         dst_port=p["tcp.dstport"], command=p["irc.request.command"].split("|")[0],
                         response_code="", detail=mask_email(mask_uri(detail.split(" HTTP/")[0] if looks_http else detail))[:160],
                         note="payload-is-HTTP (decoded as IRC by port 6667)" if looks_http else ""))
    for p in ts.fields(pcap, "smtp.req.command or smtp.response.code",
                       ["frame.number", "frame.time_epoch", "frame.time_relative", "tcp.stream", "ip.src", "ip.dst",
                        "tcp.srcport", "tcp.dstport", "smtp.req.command", "smtp.req.parameter", "smtp.response.code",
                        "smtp.rsp.parameter"]):
        cmd = p["smtp.req.command"].split("|")[0]
        is_req = bool(cmd)
        misc.append(dict(ts_utc=iso_utc(p["frame.time_epoch"]), rel_time=rel6(p["frame.time_relative"]), proto="SMTP",
                         kind="request" if is_req else "response", frame=p["frame.number"], tcp_stream=p["tcp.stream"],
                         src_ip=p["ip.src"], src_port=p["tcp.srcport"], dst_ip=p["ip.dst"], dst_port=p["tcp.dstport"],
                         command=cmd, response_code=p["smtp.response.code"] if not is_req else "",
                         detail=(redact_smtp(cmd, p["smtp.req.parameter"].split("|")[0]) if is_req
                                 else redact_smtp_response(p["smtp.response.code"], p["smtp.rsp.parameter"].split("|")[0]))[:160],
                         note=""))
    misc.sort(key=lambda m: int(m["frame"]))
    write_csv(os.path.join(a.out, "irc_smtp_activity.csv"), misc,
              ["ts_utc", "rel_time", "proto", "kind", "frame", "tcp_stream", "src_ip", "src_port", "dst_ip",
               "dst_port", "command", "response_code", "detail", "note"])

    LOG.info("[8/8] Đối chiếu Zeek (tuỳ chọn)")
    if a.zeek_dir:
        conn_log = os.path.join(a.zeek_dir, "conn.log")
        if os.path.isfile(conn_log):
            cc = crosscheck_zeek(conns, parse_zeek_conn(conn_log), tol=1.0)
            write_csv(os.path.join(a.out, "wireshark_zeek_crosscheck.csv"), cc, list(cc[0].keys()) if cc else ["conn_id"])
        else:
            LOG.warning("Không thấy %s — bỏ qua crosscheck", conn_log)

    # Tóm tắt số liệu dùng cho data_consistency_check.md (không chứa thời gian chạy -> tất định)
    tcp = [c for c in conns if c["protocol"] == "TCP"]
    summary = OrderedDict(
        pcap=pcap_name, sha256=meta["sha256"], packets=meta["packets"],
        first_utc=iso_utc(meta["first"]) if meta["first"] is not None else "",
        last_utc=iso_utc(meta["last"]) if meta["last"] is not None else "",
        tcp_streams=len(tcp), udp_streams=len(conns) - len(tcp),
        tcp_states=dict(sorted(Counter(c["tcp_state"] for c in tcp).items())),
        dup_suspect_packets=dict(sorted(dup_by_proto.items())),
        dns=dict(sorted(dstats.items())), http_requests=len(http),
        http_requests_from_infected=sum(h["direction"] == "from_infected" for h in http),
        http_requests_by_detection=dict(sorted(Counter(h["detection"] for h in http).items())),
        http_payload_heuristic_by_label_port=dict(sorted(Counter(
            f'{h["wireshark_label"]}/{h["dst_port"]}' for h in http if h["detection"] == "payload_heuristic").items())),
        smtp_request_rows=sum(m["proto"] == "SMTP" and m["kind"] == "request" for m in misc),
        smtp_response_rows=sum(m["proto"] == "SMTP" and m["kind"] == "response" for m in misc),
        irc_rows=sum(m["proto"] == "IRC" for m in misc),
        warnings=ts.warnings)
    with open(os.path.join(a.out, "extract_summary.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        f.write("\n")
    LOG.info("Xong. Tóm tắt: %s", os.path.join(a.out, "extract_summary.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
