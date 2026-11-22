# Data Consistency Check — S01 (CTU-13 Scenario 1 / Neris)

**Người thực hiện:** Thương (Network Forensics) · **Ngày:** 2026-11-16 · **TShark/capinfos:** 4.6.9 · **PCAP SHA-256:** `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36`

"Giá trị script" lấy từ output của `scripts/forensics_extract.py`. "Giá trị độc lập" lấy trực tiếp bằng capinfos/tshark trong `scripts/consistency_check.py` (không import code của extractor). Bảng máy đọc: [`consistency_values.csv`](consistency_values.csv). Lệnh tái lập: [`REPRODUCE.md`](REPRODUCE.md).

## 1. Metadata capture

| Chỉ số | Script (`metadata.txt`) | Độc lập | Lệnh độc lập | Khớp? |
|---|---|---|---|---|
| Tổng packet | 323 154 | 323 154 | `capinfos -c -M` | ✅ |
| Packet đầu (UTC) | 2011-08-10T09:01:40.475792Z | 2011-08-10 09:01:40.475792 | `TZ=UTC capinfos -a` | ✅ |
| Packet cuối (UTC) | 2011-08-10T13:49:29.289628Z | 2011-08-10 13:49:29.289628 | `TZ=UTC capinfos -e` | ✅ |
| Thời lượng | 17 268.813836 s (4 h 47 m 48.8 s) | 17 268.813836 s | `capinfos -u` | ✅ |
| Packet theo `reports/week1/lam/dataset_manifest.csv` | 323 154 | 323 154 | — | ✅ |

**Lỗi đã sửa:** `metadata.txt` cũ ghi `Earliest packet time: 2011-08-10 16:01:40.475792` — đó là **giờ local UTC+7** của máy Windows (capinfos in theo TZ máy). Bản mới chạy capinfos với `TZ=UTC` và ghi thêm dòng UTC ISO 8601.

## 2. Protocol Hierarchy

`protocol_hierarchy.txt` (script) so với lần chạy `tshark -qz io,phs` mới: **44/44 dòng thống kê giống hệt** ✅. Bảng tóm tắt trong `network_overview.md` §3 lấy từ chính file này (tỷ lệ % = frames/323 154, bytes/53 096 018).

## 3. Stream

| Chỉ số | Script (`network_connections.csv`) | Độc lập | Lệnh | Khớp? |
|---|---|---|---|---|
| Số TCP stream | 12 859 dòng `protocol=TCP` | 12 859 | `tshark -T fields -e tcp.stream \| sort -u \| wc -l` | ✅ |
| Số UDP stream | 2 758 dòng `protocol=UDP` | 2 758 | `tshark -T fields -e udp.stream \| sort -u \| wc -l` | ✅ |

PowerShell tương đương: `& $T -r $P -n -T fields -e tcp.stream | Where-Object {$_} | Sort-Object -Unique | Measure-Object`.

## 4. Top 10 conversation (`tshark -qz conv,ip`) so với `top_destinations.csv`

conv,ip xếp theo tổng frame; cột "script" = tổng `packets` của mọi stream (TCP+UDP, hai chiều) giữa máy nhiễm và IP đó trong `network_connections.csv`.

| # | IP | Frames conv,ip | Frames script | Khớp? | Số stream (top_destinations) | Port |
|---|---|---:|---:|---|---:|---|
| 1 | 213.246.53.125 | 52 584 | 52 584 | ✅ | 5 | 5296 |
| 2 | 184.154.132.106 | 46 684 | 46 684 | ✅ | 3 | 9541 |
| 3 | 212.117.171.138 | 24 569 | 24 569 | ✅ | 321 | 65500 |
| 4 | 147.32.80.9 | 22 291 | 22 291 | ✅ | 6 (UDP) | 53 |
| 5 | 174.133.57.141 | 5 945 | 5 945 | ✅ | 358 | 80 |
| 6 | 209.85.225.27 | 5 790 | 5 790 | ✅ | 965 | 25 |
| 7 | 173.192.170.88 | 5 601 | 5 601 | ✅ | 286 | 80 |
| 8 | 212.117.174.7 | 5 412 | 5 412 | ✅ | 902 | 4506 |
| 9 | 65.55.196.251 | 4 759 | 4 759 | ✅ | 26 | 443 |
| 10 | 78.129.163.119 | 4 510 | 4 510 | ✅ | 2 | 6251 |

Nhận xét: xếp hạng theo **packet** (conv,ip) và theo **stream** (top_destinations) cho hai danh sách khác nhau — 213.246.53.125 đứng đầu về packet nhưng chỉ có 5 stream; 209.85.225.27 đứng đầu về stream (965) nhưng chỉ 5 790 packet SYN. Khi trích dẫn phải nói rõ đơn vị.

## 5. DNS

| Chỉ số | Script | Độc lập | Lệnh | Khớp? |
|---|---|---|---|---|
| DNS query packet (không tính DNS nằm trong ICMP) | 58 428 | 58 949 − 521 = 58 428 | `-Y "dns.flags.response==0"` trừ `-Y "dns.flags.response==0 && icmp"` | ✅ |
| DNS response packet | 26 146 | 26 148 − 2 = 26 146 | `-Y "dns.flags.response==1"` (trừ ICMP) | ✅ |
| NXDOMAIN response | 330 | 330 | `-Y "dns.flags.rcode==3"` | ✅ |
| Query duy nhất (sau khử trùng capture) | 42 669 dòng `dns_queries_full.csv.gz` | 58 428 − 15 759 = 42 669 | phép trừ | ✅ |
| Σ `query_count` trong `dns_findings.csv` | 42 669 | 42 669 | — | ✅ |
| Cờ `dns.retransmission` của tshark trên query | 15 759 trùng capture + 13 469 gửi lại thật = 29 228 | 29 228 | `-Y "dns.flags.response==0 && dns.retransmission && !icmp"` | ✅ |
| Response mồ côi | 4 (`dns_orphan_responses.csv`) | — | — | — |

Chênh lệch 521/2 gói giữa "mọi gói có trường DNS" và số script là DNS **được trích dẫn bên trong ICMP Destination Unreachable** (không phải truy vấn mới) — đã loại có chủ đích.

## 6. HTTP / SMTP (không có IRC)

| Chỉ số | Script | Độc lập | Lệnh | Khớp? |
|---|---|---|---|---|
| HTTP request | 1 393 (`http_requests.csv`) | 1 393 | `-d tcp.port==6667,http -d tcp.port==88,http -Y http.request` | ✅ |
| HTTP request `detection=dissector` | 1 361 | 1 361 | `-Y http.request` (không decode-as) | ✅ |
| HTTP request `detection=payload_heuristic` | 32 (31 `wireshark_label=IRC` port 6667 + 1 `wireshark_label=KRB5` port 88) | 32 | (decode-as) − (mặc định) với `tcp.port in {6667,88}` | ✅ |
| SMTP command packet | 517 | 517 | `-Y smtp.req.command` | ✅ |
| `smtp.req` (gồm 126 dòng username/password base64 sau `AUTH LOGIN`) | không xuất | 643 | `-Y smtp.req` | cố ý không ghi |
| SMTP 235 | 53 | 53 | `-Y smtp.response.code==235` | ✅ |
| SMTP 535 | 10 | 10 | `-Y smtp.response.code==535` | ✅ |
| Packet TShark mặc định đếm vào `irc` | 61 | 61 | `-Y irc` | ✅ — đều là HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) |
| Lệnh IRC thật (NICK/USER/JOIN #/PRIVMSG) | 0 | 0 | `-Y 'tcp.payload contains "NICK " \|\| …'` | ✅ |

**Đối soát số HTTP request: 1 361 + 32 = 1 393.**

| Thành phần | Số request | Cách TShark nhận | `detection` / `wireshark_label` |
|---|---|---|---|
| Dissector HTTP mặc định (port 80, 8080, 81, 82, 888, 2012, 65520, SSDP 1900…) | 1 361 | `-Y http.request` | `dissector` / `HTTP` (1 355) hoặc `SSDP` (6) |
| POST `/?<hex>` tới port 6667 | 31 | chỉ khi `-d tcp.port==6667,http` | `payload_heuristic` / `IRC` |
| GET `/bd.jpg` tới 60.190.223.75:88 | 1 | chỉ khi `-d tcp.port==88,http` | `payload_heuristic` / `KRB5` |
| **Tổng** | **1 393** | `-d tcp.port==6667,http -d tcp.port==88,http -Y http.request` | |

Lệnh tái lập (bash; PowerShell thay `$T` bằng `& "C:\Program Files\Wireshark\tshark.exe"`):

```bash
$T -r $P -n -Y http.request -T fields -e frame.number | wc -l                                            # 1361
$T -r $P -n -d tcp.port==6667,http -d tcp.port==88,http -Y http.request -T fields -e frame.number | wc -l # 1393
# 32 frame chỉ thấy khi ép decode + nhãn mặc định của chúng
$T -r $P -n -Y "frame.number in {2294,3341,3820,4556}" -T fields -e frame.number -e tcp.dstport -e _ws.col.protocol
```

Ý nghĩa: mọi thống kê "theo nhãn giao thức" của Wireshark/Zeek (Protocol Hierarchy, `-Y irc`, `service` của Zeek) đều xếp 31 request port 6667 là IRC và bỏ sót request port 88. Phân loại phải dựa vào payload (dòng đầu là request line HTTP), không dựa vào port. Với 106 packet có payload trên port 6667: 72 `POST`, 30 `HTTP/1.1 200`, 4 RST kèm text của middlebox (frame 8963, 220353, 220362, 220376) — **0** lệnh IRC.

## 7. SHA-256 PCAP

| Nguồn | Giá trị | = hash tính lại? |
|---|---|---|
| Tính lại (`sha256sum` / `Get-FileHash`) | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` | — |
| `metadata.txt` | như trên | ✅ |
| `datasets/dataset_manifest.csv` | như trên | ✅ |
| `reports/week1/lam/dataset_manifest.csv` | như trên | ✅ |
| `evidence/findings/FND-001.md` (Quý) | như trên | ✅ |
| `reports/week1/thi/behavior_evidence.md` | như trên | ✅ (kiểm tra thủ công) |

Metadata khác: `datasets/dataset_manifest.csv` đã đổi `date` `11/12/2026` → `2026-11-12`, bỏ BOM UTF-8. So với manifest của Lâm: khác schema (cột), `capture_duration=04:47:48` của Lâm = 17 268.8 s làm tròn xuống giây ✅; `pcap_size_mb=58` ✅ (58 266 506 byte). Chi tiết khác biệt ghi ở `reports/week1/thuong/handoff.md`.

## 8. Gói trùng do capture và ảnh hưởng

PCAP được bắt trên interface của VM nhiễm; **gần như mọi gói đi ra** từ 147.32.84.165 xuất hiện **2 lần** (cùng `ip.id`, cùng nội dung). Phần lớn cách nhau vài µs, một phần nhỏ cách 0.5–1.4 s (có thể do hàng đợi giới hạn băng thông 20 kbps của thí nghiệm — **chưa xác nhận**).

| Định nghĩa | Số gói | Nguồn |
|---|---:|---|
| Trùng < 1 ms, TCP (script) | 81 378 | `extract_summary.json` |
| Trùng < 1 ms, UDP (script) | 16 364 | `extract_summary.json` |
| Tổng script (TCP+UDP) | **97 742** (30.2 % tổng packet) | `extract_summary.json` |
| Bộ đếm độc lập (khoá `ip.id+src+dst+proto+ip.len+ip.checksum`, mọi gói IP) | 97 768 | `consistency_check.py` |
| Chênh lệch | 26 (0.008 %) | **không phải lỗi** — giải thích chi tiết ngay dưới bảng (22 TCP `ip.id=0` + 4 ICMP echo/IGMP) |
| Trùng cách 1 ms–2 s (độc lập) | 22 023 | gồm bản sao trễ + một phần trùng `ip.id` tự nhiên |
| Ví dụ trùng trễ | stream 1299: frame 22718/22807 cùng `ip.id 0x2e22`, Δt = 0.566 s | `tshark -Y "tcp.stream==1299"` |

**Vì sao lệch 26 gói (97 768 − 97 742) — không phải lỗi script.** Hai bộ đếm dùng khoá khác nhau có chủ đích (để kiểm tra chéo):

| Nhóm | Bộ đếm độc lập (khoá IP) | Script (khoá TCP/UDP) | Chênh | Lý do |
|---|---:|---:|---:|---|
| TCP thường | 81 378 | 81 378 | 0 | khớp |
| TCP có `ip.id = 0x0000` (gói **vào** từ server: 20 SYN/ACK, 1 ACK, 1 RST; 16 từ 173.192.170.88, 6 từ 5 IP khác) | 22 | 0 | **+22** | Các gói thuộc **kết nối khác nhau** (khác port, `tcp.seq`) nhưng header IP giống hệt (id 0, cùng len/TTL ⇒ cùng checksum), đến cách nhau < 1 ms. Khoá IP coi là trùng ⇒ **dương tính giả của bộ đếm độc lập**; script so thêm port + `tcp.seq` + cờ nên đúng là không trùng. Ví dụ frame 2896 vs 2895 (94.127.76.180:80 → port 1316 / 1317). |
| UDP | 16 343 | 16 343 | 0 | khớp |
| ICMP type 3 có gói UDP bị trích dẫn bên trong | 21 | 21 (xếp vào UDP vì TShark điền `udp.*` từ gói trích dẫn) | 0 | cả hai đều đếm |
| ICMP echo reply (frame 244826, 284652) + IGMPv3 (frame 68, 72) | 4 | 0 | **+4** | ICMP/IGMP không có port, không có `tcp.seq` ⇒ `DupDetector` của script (chỉ xét TCP/UDP) bỏ qua |
| **Tổng** | **97 768** | **97 742** | **+26** | 22 + 4 |

Kết luận: 4 gói là bản sao thật ở giao thức script không xét (không ảnh hưởng chỉ số TCP/UDP nào); 22 gói là trùng giả do khoá IP quá thô. Số 97 742 của script là số đúng cho TCP/UDP. Lệnh kiểm tra: `$T -r $P -n -Y "ip.id==0 && tcp && ip.dst==147.32.84.165" -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.flags -e ip.checksum`.

Ảnh hưởng tới các con số:
- **Packet/bytes** (`io,phs`, `conv,ip`, `packets`, `bytes_*`): bị thổi phồng ~30 %. Dùng `packets_dedup` khi cần số gói "thật".
- **`tcp.analysis.retransmission`** (65 274 gói) và số SYN (65 467): phần lớn là bản sao capture, **không** phải retransmission mạng. Không dùng chỉ số này để kết luận mất gói.
- **Số stream**: **không** ảnh hưởng (bản sao nằm cùng stream).
- **DNS**: đã khử trùng (15 759 query trùng); nếu không khử, `query_count` của mỗi domain gần gấp đôi (lỗi của bản `dns_findings.csv` cũ).
- **HTTP/SMTP**: TShark không phân tích lại payload của bản sao (gắn cờ retransmission) nên không đếm trùng.

## 9. Chênh lệch "gấp đúng 2 lần": Zeek 1930/1804 vs TShark 965/902

| Đích | TShark stream | SYN/stream (kể cả trùng) | ip.id khác nhau/stream | Khoảng cách SYN | Zeek conn (Quý) | Mô phỏng "gói > start+5 s ⇒ conn mới" |
|---|---:|---|---|---|---:|---:|
| 209.85.225.27:25 | 965 | 6 (965/965 stream) | 3 | +3 s, +6 s (965/965) | 1 930 | **1 930** |
| 212.117.174.7:4506 | 902 | 6 (902/902 stream) | 3 | +3 s, +6 s (902/902) | 1 804 | **1 804** |

Ví dụ stream 406 (FND-002(Quý)): frame 6502/6503 (t = 977.980346, `ip.id 0x0ad4`), 6526/6527 (t + 3.0045 s, `0x0adf`), 6583/6584 (t + 9.0131 s, `0x0af6`) — cùng sport 1566, cùng ISN 605998363 ⇒ **một** lần thử kết nối với 2 lần gửi lại SYN kiểu Windows XP (3 s, 6 s).

Giải thích (INFERRED, độ tin cậy Cao): Zeek coi SYN không được trả lời quá ~5 s là một "attempt" kết thúc, nên SYN thứ 3 (t + 9 s) mở connection mới ⇒ 2 Zeek conn/stream: conn A = SYN#1+SYN#2 (thời lượng ≈ 3 s), conn B = SYN#3 (≈ 0 s). Kiểm chứng: (1) mô phỏng cho đúng 1 930/1 804; (2) thời lượng trung bình mô phỏng 1.515704 s / 1.514801 s ≈ Zeek 1.516489 s / 1.515641 s (Quý); (3) `orig_ip_bytes` Zeek 277 920 = 5 790 gói × 48 byte IP ⇒ Zeek cũng đếm cả bản sao capture. **Chưa kiểm chứng trực tiếp** bằng `conn.log` (máy Thương không có Zeek log) — Quý chạy `forensics_extract.py --zeek-dir data/processed/scenario-01-neris/zeek` để có `wireshark_zeek_crosscheck.csv` (cột `match_type` sẽ là `1:2`).

**Đơn vị dùng cho mục đích nào:**

| Mục đích | Đơn vị nên dùng | Lý do |
|---|---|---|
| Đếm "số lần thử kết nối" của bot | TCP stream (hoặc số ISN khác nhau) | 1 stream = 1 socket/ISN; không bị ảnh hưởng timeout |
| Detection/alert dựa trên Zeek | Zeek conn (ghi rõ "Zeek conn") | khớp với log mà rule chạy trên đó |
| Ground truth / metric với nhãn CTU | Argus labeled flow (ghép theo 5-tuple + thời gian) | nhãn gắn vào flow, không gắn vào stream |
| Khối lượng | packet/byte **đã khử trùng** | tránh thổi phồng 2× |

## 10. Chênh lệch chưa giải thích được / cần kiểm tra thêm

| Chênh lệch | Trạng thái | Hướng kiểm tra |
|---|---|---|
| Thời lượng trung bình mô phỏng lệch Zeek ~0.0008 s | chưa giải thích hết | so trực tiếp với `conn.log` qua `--zeek-dir`; Zeek bỏ 1 bản ghi thiếu `duration` |
| Nguyên nhân bản sao trễ 0.5–1.4 s | chưa giải thích được | đối chiếu tài liệu CTU về cấu hình capture/giới hạn băng thông |
| Thời điểm bắt đầu trong `ground_truth_notes.md` (Lâm): "11:10:48 CEST (09:10:48 UTC)" ≠ packet đầu 09:01:40.475792Z | lệch tài liệu | Lâm đối chiếu nguồn; PCAP: NBNS đầu tiên của bot 09:04:23.241037Z (frame 15) |
