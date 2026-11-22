# Review Response — PR #7 (Lâm) · Network Forensics tuần 1 (Thương)

**Nhánh:** `thuong/week1` (từ `dev` @ `0f3bc15`) · **Ngày:** 2026-11-16 · **PCAP SHA-256:** `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36`

Commit (theo thứ tự): **C1** `fix(forensics): tshark error handling, TCP state and DNS matching` · **C2** `test(forensics): unit tests for extraction helpers` · **C3** `data(forensics): regenerate S01 outputs and reproduction guide` · **C4** `docs(forensics): complete network overview, packet evidence and consistency check`. (Hash commit điền khi trả lời PR.)

## 1. Báo cáo và bằng chứng

| Ý review | Đã làm | File / commit | Cách kiểm tra |
|---|---|---|---|
| Hoàn thiện `network_overview.md`, đủ số liệu và nhận xét | Viết lại 8 mục: metadata UTC, host (SARUMAN/VirtualBox/Cisco, frame căn cứ), protocol distribution packet+byte, trạng thái TCP + top 15 đích (port, byte 2 chiều), DNS (khử trùng, NXDOMAIN, 78.3 % external_direct), HTTP/SMTP/IRC (kết luận không có IRC), 8 candidate (≥ 2 đặc trưng, liên kết EVD), giới hạn; mỗi mục có **Nhận xét** | `network_overview.md` · C4 | Mọi số có trong `extract_summary.json`/CSV; đối chiếu `data_consistency_check.md` |
| Hoàn thiện `packet_evidence.md`: finding thực tế, frame, timestamp, TCP stream, evidence | 20 evidence EVD-006..EVD-025, mỗi mục có finding (ghi nguồn ID), frame, stream, ts UTC + relative, src→dst, filter Wireshark, lệnh tshark, Observation/Interpretation/lành tính, mức, confidence, trạng thái; bảng DNS → connection; mục "Ảnh Wireshark cần chụp" | `packet_evidence.md`, `sn_php_requests.csv`, `dns_to_connection.csv`, `http_pe_responses.csv` · C3, C4 | Chạy lệnh tshark trong từng EVD; 5 frame ngẫu nhiên đã tra lại (mục 4) |
| Xoá mọi placeholder | Không còn chuỗi mẫu `<dán…>` / `<tiêu đề…>`, ô bảng trống, `(Tóm tắt…)`, ID mẫu `S01-F00x` | C4 | `grep -nE '<dán\|<tiêu đề\|\(Tóm tắt\|TODO\|\| \|' analysis/network-forensics/S01/*.md` → chỉ còn chính dòng mô tả lệnh grep này |

## 2. Extraction script (`scripts/forensics_extract.py`)

| Ý review | Đã làm | File / commit | Cách kiểm tra |
|---|---|---|---|
| Xử lý lỗi TShark | Dò tshark/capinfos theo `--tshark`, `$TSHARK`, PATH, `C:\Program Files\Wireshark\`; kiểm tra PCAP tồn tại/không rỗng/đủ header; mọi lệnh kiểm `returncode`, bắt `stderr` (bỏ `Running as user "root"`), timeout; kiểm tra field theo `tshark -G fields` và báo tên field + phiên bản; phát hiện `cut short` → cảnh báo + ghi `metadata.txt`; capinfos lỗi chỉ cảnh báo; `logging` + `--verbose`; mã thoát 3/4/5/6 | `scripts/forensics_extract.py` · C1 | `pytest -q tests/test_forensics_extract.py -k "exec or require or check_pcap or exit_codes"` |
| Rà soát logic TCP state | Initiator = SYN (không ACK) đầu tiên; không SYN → `PARTIAL` + `initiator_assumed`; trạng thái `S0/REJ/EST_FIN/EST_RST/EST_OPEN/SYN_ACK_NO_ACK/PARTIAL`; cột `syn_count, synack_count, rst_by, fin_by, retrans_count, dup_suspect_count, packets_dedup`; cờ đọc được `1/0` và `True/False`; ánh xạ Zeek trong `REPRODUCE.md` §6. **Lỗi cũ:** initiator lấy theo gói đầu, `ESTABLISHED+FIN` không cần ACK hoàn tất, không phân biệt bên RST | C1 | 9 test `test_tcp_*` (mỗi nhánh 1 test) |
| Rà soát DNS query/response matching | Khoá `dns.response_to` (TShark 1 lượt không điền `dns.response_in`), fallback (id, qname, 5-tuple đảo); gộp query trùng capture (Δt < 1 ms) vào `dup_frames`; retransmission thật giữ dòng riêng; `no-response`; `dns_orphan_responses.csv`; `answers_A` chỉ lấy answer section (sửa lỗi lẫn glue `216.239.32.10`); `resolver_type`; loại DNS trong ICMP. **Lỗi cũ:** khoá `(id, qname, ip)` ghép sai khi id lặp, query trùng bị đếm 2 lần, `dns_findings.csv` 9.5 MB | C1, C3 | `test_split_dns_answers_*`, `test_build_dns_*`, `test_match_dns_*`; `data_consistency_check.md` §5 |
| Chạy kiểm thử lại trên Scenario 1 + hướng dẫn tái lập | Chạy lại toàn bộ (≈ 57 s), ghi đè output; `REPRODUCE.md` có phiên bản công cụ, SHA-256 input, lệnh PowerShell + bash, đơn vị từng file; chạy lại lần 2 → hash mọi output giống hệt; thêm `tests/test_forensics_extract.py` (42 test, gồm test tích hợp PCAP tổng hợp scapy) | `REPRODUCE.md`, `tests/test_forensics_extract.py`, output S01 · C2, C3 | `pytest -q` → 47 passed; `sha256sum analysis/network-forensics/S01/*.csv*` trước/sau |
| (thêm) Timestamp chuẩn nhóm | Mọi CSV có `ts_utc` (`…ffffffZ`, Decimal, không mất chính xác) + `rel_time` 6 chữ số; `network_connections.csv` thêm `first_frame, last_frame, ts_start_utc, rel_start` | C1, C3 | `test_iso_utc_*`; mở CSV |
| (thêm) HTTP trên port phi chuẩn | `-d tcp.port==6667,http -d tcp.port==88,http` → 1 393 request (mặc định 1 361 bỏ sót 31 POST CB2 + 1 GET PE). `http_requests.csv` thêm cột `detection` (`dissector` 1 361 / `payload_heuristic` 32) và `wireshark_label` (`IRC` 31, `KRB5` 1); EVD-024 (kênh HTTP-over-6667, 17 IP), EVD-025 (`/bd.jpg` port 88 = PE ngụy trang JPEG) | C1, C3, C4 | `test_http_detection_*`, `test_http_rows_detection_columns`; `data_consistency_check.md` §6 (1 361 + 32 = 1 393) |
| (thêm) Riêng tư | Email che local-part, AUTH chỉ giữ cơ chế, không ghi dòng base64; query string ≥ 16 ký tự che sau 4 ký tự | C1 | `test_redact_smtp_*`, `test_mask_*`; grep mục 4 |
| (thêm) `--zeek-dir` | Sinh `wireshark_zeek_crosscheck.csv` (5-tuple + start ±1 s, đếm Zeek conn trong khoảng stream) | C1 | `test_crosscheck_*`; **chưa chạy trên dữ liệu thật** (máy Thương không có Zeek log) — giao Quý |

## 3. Kiểm tra dữ liệu

| Ý review | Đã làm | File / commit | Cách kiểm tra |
|---|---|---|---|
| Đối chiếu thống kê với Wireshark | `scripts/consistency_check.py` gọi capinfos/tshark độc lập: packet, mốc UTC, thời lượng, io,phs, số TCP/UDP stream, top 10 conv,ip, DNS query/response/NXDOMAIN, HTTP request, SMTP command/235/535, IRC → **tất cả khớp**; bảng + giải thích ở `data_consistency_check.md` | `scripts/consistency_check.py`, `consistency_values.csv`, `data_consistency_check.md` · C3, C4 | `python scripts/consistency_check.py <pcap> --out analysis/network-forensics/S01` (cột `match`) |
| Kiểm tra metadata, hash PCAP, CSV | SHA-256 khớp ở `metadata.txt`, 2 manifest, `FND-001.md` (Quý), báo cáo Thi; sửa `metadata.txt` ghi giờ local → UTC; manifest: `date` → `2026-11-12`, bỏ BOM; khác biệt với manifest của Lâm ghi trong handoff | `metadata.txt`, `datasets/dataset_manifest.csv`, `reports/week1/thuong/handoff.md` §6 · C3 | `data_consistency_check.md` §1, §7 |
| (thêm) Gói trùng | Định lượng 97 742 gói (30.2 %) trùng < 1 ms, ảnh hưởng tới từng chỉ số | `data_consistency_check.md` §8 | so bộ đếm độc lập (97 768; lệch 26 = 22 gói TCP `ip.id=0` bị khoá IP đếm nhầm là trùng + 4 ICMP echo/IGMP mà script không xét — `data_consistency_check.md` §8) |
| (thêm) Chênh lệch ×2 Zeek/TShark | 1 stream = 3 SYN (+3 s, +6 s); quy tắc "gói > start+5 s ⇒ conn mới" cho đúng 1 930/1 804; đơn vị dùng cho mục đích nào | `data_consistency_check.md` §9 | `consistency_values.csv` dòng `zeek-like conns` |

## 4. Kiểm tra cuối đã chạy

| Kiểm tra | Kết quả |
|---|---|
| Chạy lại `REPRODUCE.md` từ đầu, so SHA-256 mọi output | giống hệt (18/18 file `*.csv *.csv.gz *.txt *.json`) |
| 5 frame ngẫu nhiên trong `packet_evidence.md` tra lại bằng tshark | chọn bằng `random.Random(20261116).sample`: 491, 1959, 3213, 4491, 137134 — cả 5 khớp frame, stream, ts UTC, relative, src/dst |
| `pytest -q` | 47 passed |
| grep placeholder / `TODO` / base64 sau `AUTH LOGIN` (kể cả prompt 334) / email đầy đủ / đường dẫn tuyệt đối ổ đĩa Windows / đoạn hex thật của bot ID | không có |
| `git status`, `git diff --cached --stat` | không có `.pcap`, không file > 5 MB (lớn nhất `network_connections.csv` ≈ 4.5 MB) |

## 5. Phát hiện cần nhóm lưu ý (chi tiết: `reports/week1/thuong/handoff.md`)

1. Host tải PE là **`nocomcom.com`**, không phải `nomcom.com` (IOC-009..012 cần sửa).
2. Kênh 212.117.171.138:65500 là **SOCKS5 ngược**: C2 ra lệnh bot kết nối `smtp.aol.com:587`, bot chuyển tiếp banner/EHLO trong < 0.4 ms (EVD-007).
3. **Không có IRC**: 61 packet mang nhãn `irc` là HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port); kênh này gồm 31 POST tới 17 IP — ứng viên C2 mới NF-07 (EVD-024).
4. Zeek 1930/1804 = 2 × TCP stream 965/902 (mỗi lần thử có 3 SYN).
5. ≈ 30 % packet là bản sao capture — các thống kê packet/retransmission cần khử trùng.

## 6. Bổ sung: HTTP trên port phi chuẩn (kiểm tra `http_requests.csv` vs `tshark -Y http.request`)

| Yêu cầu | Đã làm | File | Cách kiểm tra |
|---|---|---|---|
| Thêm cột `detection` và `wireshark_label` | `detection` = `dissector` (1 361) / `payload_heuristic` (32); `wireshark_label` = cột Protocol TShark mặc định (`HTTP` 1 355, `SSDP` 6, `IRC` 31, `KRB5` 1); `extract_summary.json` có `http_requests_by_detection` | `scripts/forensics_extract.py`, `http_requests.csv`, `sn_php_requests.csv` | `pytest -q -k http_` ; `consistency_values.csv` 2 dòng `detection=` |
| Rà mọi chỗ nói "IRC" | Đổi thành "HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)", mức OBSERVED; giữ nguyên tên file `irc_smtp_activity.csv` và filter `irc` (là tên field TShark) | `network_overview.md`, `packet_evidence.md`, `data_consistency_check.md`, `REPRODUCE.md`, `reports/week1/thuong/handoff.md` | `grep -n -i irc` trên các file này |
| EVD HTTP POST port 6667 | **EVD-024**: 31 request, 17 IP, 09:09:22.395329Z → 13:46:46.039076Z, frame 2294/3341/4556, query hex 162–180 ký tự (INFERRED mã hóa, không giải mã) | `packet_evidence.md` | lệnh tshark trong EVD-024 |
| EVD `/bd.jpg` port 88 | **EVD-025**: frame 3820 → 3895, `image/jpeg` nhưng body bắt đầu `4D 5A`; cùng IP 60.190.223.75 với `/sn.php` port 888 và `/kp.exe` port 2012 | `packet_evidence.md` | lệnh tshark trong EVD-025 |
| 1 361 + 32 = 1 393 | Bảng đối soát + lệnh tái lập | `data_consistency_check.md` §6 | `consistency_check.py` → 40/41 dòng khớp (dòng lệch duy nhất là bộ đếm bản sao: 22 TCP `ip.id=0` + 4 ICMP echo/IGMP, giải thích ở §8 — không phải lỗi) |
| Handoff | Thi: NF-07 kênh HTTP-over-6667 là ứng viên C2, `/bd.jpg` vào timeline; Lâm: đề xuất IOC 16 IP còn lại + pattern + URL/hash `/bd.jpg`, cập nhật IOC-004; Quý: detector theo nhãn giao thức/port phân loại sai | `reports/week1/thuong/handoff.md` §1, §2, §3, §4, §5 (dòng 13) | đọc handoff |
