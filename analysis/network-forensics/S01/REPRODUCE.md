# REPRODUCE — Network Forensics S01 (CTU-13 Scenario 1 / Neris)

Hướng dẫn tái lập **toàn bộ** output trong `analysis/network-forensics/S01/` từ PCAP gốc. Mọi bước chỉ **đọc** PCAP; không export object, không ghi payload ra đĩa (SHA-256 body HTTP tính trong bộ nhớ).

## 1. Môi trường đã dùng (lần chạy 2026-11-16)

| Thành phần | Phiên bản |
|---|---|
| OS | Windows 11 Education 10.0.26300 (Git Bash + PowerShell 5.1) |
| TShark | `TShark (Wireshark) 4.6.9 (v4.6.9-0-g2d548b197c75)` |
| capinfos | `Capinfos (Wireshark) 4.6.9 (v4.6.9-0-g2d548b197c75)` |
| Python | 3.12.10 (venv `.venv`, đã bị `.gitignore`) |
| pytest / scapy | 9.2.0 / 2.8.0 (chỉ dùng cho test) |
| Thời gian chạy | `forensics_extract.py` ≈ 57 s; `consistency_check.py` ≈ 61 s |

## 2. Input và kiểm tra toàn vẹn

| Mục | Giá trị |
|---|---|
| File | `botnet-capture-20110810-neris.pcap` (58 266 506 byte) |
| SHA-256 bắt buộc | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` |
| Đường dẫn chuẩn nhóm (README) | `data/raw/scenario-01-neris/pcap/` |
| Đường dẫn trên máy Thương | `datasets/scenario-01-neris/pcap/` |
| Bị ignore? | `git check-ignore -v datasets/scenario-01-neris/pcap/botnet-capture-20110810-neris.pcap` → `.gitignore:41:*.pcap` |

Script nhận PCAP qua tham số; **nếu bỏ trống** sẽ thử lần lượt `data/raw/scenario-01-neris/pcap/<file>` rồi `datasets/scenario-01-neris/pcap/<file>`. Không di chuyển file. Nếu SHA-256 khác giá trị trên → **dừng**, không dùng kết quả.

## 3. Lệnh — Windows PowerShell

```powershell
cd <thư mục repo NT140>
python -m venv .venv
.\.venv\Scripts\python -m pip install pytest scapy
$PCAP = "datasets\scenario-01-neris\pcap\botnet-capture-20110810-neris.pcap"   # hoặc data\raw\...
(Get-FileHash $PCAP -Algorithm SHA256).Hash.ToLower()                            # phải = b89cd593...6a36
$env:TSHARK = "C:\Program Files\Wireshark\tshark.exe"                             # tuỳ chọn, script tự dò
.\.venv\Scripts\python scripts\forensics_extract.py $PCAP --scenario S01 --infected 147.32.84.165 --out analysis\network-forensics\S01
.\.venv\Scripts\python scripts\consistency_check.py $PCAP --out analysis\network-forensics\S01 --infected 147.32.84.165 --repo-root .
.\.venv\Scripts\python -m pytest -q
```

## 4. Lệnh — Ubuntu bash

```bash
cd ~/NT140
python3 -m venv .venv && .venv/bin/pip install pytest scapy
PCAP=data/raw/scenario-01-neris/pcap/botnet-capture-20110810-neris.pcap
sha256sum "$PCAP"                       # phải = b89cd593...6a36
.venv/bin/python scripts/forensics_extract.py "$PCAP" --scenario S01 --infected 147.32.84.165 \
    --out analysis/network-forensics/S01 [--zeek-dir data/processed/scenario-01-neris/zeek]
.venv/bin/python scripts/consistency_check.py "$PCAP" --out analysis/network-forensics/S01 \
    --infected 147.32.84.165 --repo-root .
.venv/bin/python -m pytest -q
```

Tuỳ chọn khác: `--verbose` (log DEBUG kèm từng lệnh tshark), `--tshark/--capinfos` (đường dẫn công cụ), `--timeout` (mặc định 1800 s/lệnh), `--resolver` (mặc định `147.32.80.9`), `--http-decode-ports` (mặc định `6667,88`), `--zeek-dir` (sinh `wireshark_zeek_crosscheck.csv`).

Mã thoát: `0` OK · `3` không tìm thấy tshark · `4` PCAP không tồn tại/rỗng/thiếu header · `5` field TShark không có trong phiên bản đang dùng (thông báo nêu tên field + phiên bản) · `6` TShark/capinfos lỗi (returncode ≠ 0, timeout). PCAP bị cắt cụt (`appears to have been cut short`) → chỉ cảnh báo và ghi vào dòng `Warnings:` của `metadata.txt`. capinfos lỗi → cảnh báo, vẫn chạy tiếp.

## 5. Output và đơn vị đếm

| File | Đơn vị 1 dòng | Ghi chú |
|---|---|---|
| `metadata.txt` | — | capinfos chạy với `TZ=UTC` (bản cũ ghi **giờ local +07:00** — đã sửa), SHA-256, mốc UTC microsecond |
| `protocol_hierarchy.txt`, `conversations_*.txt`, `endpoints_ip.txt` | — | đếm **packet** (có cả gói trùng do capture) |
| `network_connections.csv` | 1 **TCP stream** (`tcp.stream`) hoặc 1 **UDP stream** (`udp.stream`) | ≠ Zeek connection ≠ Argus labeled flow |
| `top_destinations.csv` | 1 (IP đích, giao thức) gộp các stream do máy nhiễm khởi tạo | cột `streams` (trước đây `connections`) |
| `dns_queries_full.csv.gz` | 1 **DNS query duy nhất** (đã gộp bản sao do capture) | gzip tất định (`mtime=0`) |
| `dns_findings.csv` | 1 **query name** | `query_count` = số query duy nhất (không đếm trùng capture) |
| `dns_orphan_responses.csv` | 1 response không ghép được | S01: 4 dòng |
| `http_requests.csv` | 1 **HTTP request** | query string ≥ 16 ký tự bị che sau 4 ký tự; `detection` = `dissector` (TShark mặc định nhận) / `payload_heuristic` (chỉ nhận khi ép decode-as); `wireshark_label` = cột Protocol TShark mặc định (vd. `HTTP`, `SSDP`, `IRC`, `KRB5`) |
| `http_pe_responses.csv` | 1 HTTP response có body `MZ`/octet-stream | prefix 16 byte + SHA-256 tính trong bộ nhớ |
| `sn_php_requests.csv` | 1 request `/sn.php` | tập con của `http_requests.csv` |
| `dns_to_connection.csv` | 1 cặp (HTTP Host, IP đích, port) | DNS gần nhất trước request → kết nối |
| `irc_smtp_activity.csv` | 1 **packet** lệnh/response SMTP hoặc packet TShark gán nhãn `irc` (ở S01 đều là HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port), cột `note`) | email che local-part; AUTH chỉ giữ cơ chế, không ghi dòng base64 |
| `extract_summary.json` | — | tổng hợp số đếm, không chứa thời gian chạy |
| `consistency_values.csv` | 1 chỉ số đối chiếu | sinh bởi `consistency_check.py` |

Mọi CSV có `ts_utc` (`YYYY-MM-DDTHH:MM:SS.ffffffZ`) và `rel_time` (giây từ đầu capture, 6 chữ số). `network_connections.csv` có thêm `first_frame`, `last_frame`, `ts_start_utc`, `rel_start`, `ts_end_utc`, `rel_end`.

## 6. Logic đã rà soát

**TCP state** (`classify_tcp`): initiator = nguồn của gói SYN (không ACK) **đầu tiên** trong stream; không có SYN → `PARTIAL`, initiator = gói đầu (cột `initiator_assumed=yes`). Cờ đọc được cả dạng `1/0` và `True/False`.

| State script | Điều kiện | Gần đúng Zeek `conn_state` |
|---|---|---|
| `S0` | có SYN, bên đáp không gửi gói nào | `S0` |
| `REJ` | có SYN, bên đáp gửi RST, chưa bắt tay xong | `REJ` (hoặc `RSTOS0`/`RSTRH` tuỳ chiều) |
| `EST_FIN` | SYN → SYN-ACK (bên đáp) → ACK (bên khởi tạo); sự kiện kết thúc cuối cùng là FIN | `SF` (hoặc `S2`/`S3` nếu chỉ một bên FIN) |
| `EST_RST` | bắt tay đủ; có RST (cột `rst_by` = `orig`/`resp`) | `RSTO` (orig) / `RSTR` (resp) |
| `EST_OPEN` | bắt tay đủ, không thấy FIN/RST | `S1` |
| `SYN_ACK_NO_ACK` | có SYN-ACK nhưng không thấy ACK hoàn tất | `SH`/`S1` (half-open) |
| `PARTIAL` | không thấy SYN khởi tạo (bắt đầu giữa chừng) | `OTH` / `SHR`… |

Cột phụ: `syn_count`, `synack_count`, `rst_by`, `fin_by`, `retrans_count` (= số gói có `tcp.analysis.retransmission`, **bao gồm** bản sao do capture), `dup_suspect_count` (gói giống hệt gói trước cùng `ip.id, ip.src, ip.dst, port, tcp.seq, tcp.len, flags`, cách < 1 ms), `packets_dedup = packets − dup_suspect_count`.

Lưu ý quan trọng: **Zeek có thể tách 1 TCP stream thành nhiều connection**. Ở S01, mỗi stream SYN-only có 3 SYN (t, t+3 s, t+9 s); quy tắc "gói vượt start+5 s mở connection mới" cho đúng 1930/1804 connection như Zeek (xem `data_consistency_check.md`).

**DNS matching**: khoá chính là `dns.response_to` của response (TShark một lượt **không** điền `dns.response_in` trên query — đã kiểm chứng ở frame 22/24), fallback `(dns.id, qname, 5-tuple đảo)` khi field không có. Query trùng do capture (cùng `dns.id`, qname, qtype, 5-tuple, Δt < 1 ms) gộp thành 1 dòng, frame còn lại ở `dup_frames`. Query gửi lại thật (Δt ≥ 1 ms) giữ dòng riêng, `notes=retransmission-of=<frame>`. `answers_A` chỉ lấy RR thuộc **answer section** (dựa `dns.count.answers` + thứ tự `dns.resp.type`), không lẫn glue của additional section (ví dụ `216.239.32.10` ở frame 39 nay nằm ở `additional_A_count`). `resolver_type` = `internal` nếu đích là `147.32.80.9`, ngược lại `external_direct`. DNS nằm trong ICMP error (521 query, 2 response) bị loại bằng filter `dns && !icmp`.

**HTTP**: TShark mặc định không nhận HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) và 88 (nhận nhầm là KRB5). Bước HTTP thêm `-d tcp.port==6667,http -d tcp.port==88,http` → 1 393 request = 1 361 `dissector` + 32 `payload_heuristic`. Script chạy thêm 1 lượt **không** decode-as để lấy tập frame mặc định và `_ws.col.protocol` cho cột `wireshark_label`.

## 7. Kiểm tra tái lập (đã chạy 2026-11-16)

1. Chạy lại toàn bộ mục 3 từ đầu; so SHA-256 mọi file `*.csv *.csv.gz *.txt *.json` trước/sau: **giống hệt** (output không chứa thời gian chạy).
2. `pytest -q` → 47 passed (42 test mới trong `tests/test_forensics_extract.py`, gồm 1 test tích hợp tạo PCAP tổng hợp bằng scapy trong `tmp_path`).

## 8. Lệnh tshark tra cứu nhanh (dùng trong `packet_evidence.md`)

```bash
T=tshark; P=<đường dẫn PCAP>
# 1 frame, thời gian UTC + relative + stream
$T -r $P -n -Y 'frame.number==2297' -T fields -e frame.number -e frame.time_epoch -e frame.time_relative -e tcp.stream -e ip.src -e ip.dst
# HTTP trên 6667 (CB2)
$T -r $P -n -d tcp.port==6667,http -Y 'tcp.stream==88 && http'
# prefix body (không ghi ra đĩa)
$T -r $P -n -Y 'frame.number==899' -T fields -e http.file_data | cut -c1-32
```
Trên Windows Git Bash cần `export MSYS_NO_PATHCONV=1` để filter có dấu `/` không bị đổi thành đường dẫn.
