# Handoff tuần 1 — Thương (Network Forensics) · S01 Neris

**Ngày:** 2026-11-16 · **Nhánh:** `thuong/week1` · **PCAP SHA-256:** `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36`
Tài liệu chính: [`network_overview.md`](../../../analysis/network-forensics/S01/network_overview.md) · [`packet_evidence.md`](../../../analysis/network-forensics/S01/packet_evidence.md) · [`data_consistency_check.md`](../../../analysis/network-forensics/S01/data_consistency_check.md) · [`REPRODUCE.md`](../../../analysis/network-forensics/S01/REPRODUCE.md) · [`REVIEW_RESPONSE.md`](../../../analysis/network-forensics/S01/REVIEW_RESPONSE.md)

> Thương **không sửa** file của thành viên khác. Mọi sai lệch phát hiện được liệt kê ở §5 để chủ file tự cập nhật.

## 1. Việc giao

### Thi (Malware Communication)
1. Đưa chuỗi **CB2 → SOCKS5 → SMTP AOL** vào `malware_timeline.csv`: frame 2297 → 2303 → 3204/3212/3213/3216 → 3222/3224 → 3227 → 3237/3238 → 3241/3242 (EVD-006, EVD-007; mốc UTC trong `packet_evidence.md`).
2. Cập nhật FND-003: response của frame 1744 (`/bl/client.exe`) và 2024 (`/sv/fjuivgfhurew.exe`) là PE đầy đủ (frame 1918, 2241); Host đúng là `nocomcom.com`.
3. Đính chính mục "IRC 61 packet" (§1.1 `behavior_evidence.md`) thành "**HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)**" — mức OBSERVED, 0 lệnh IRC (EVD-022).
4. **Kênh HTTP-over-6667 là ứng viên C2 mới (NF-07, EVD-024):** FND-001 hiện chỉ mô tả 1 phiên tới 200.171.4.222. PCAP có **31 HTTP POST `/?<hex>` tới 17 IP khác nhau** trên port 6667 (09:09:22.395329Z → 13:46:46.039076Z, frame ví dụ 2294/3341/4556), 30 response đều `CB2=212.117.171.138:65500`. Đề nghị mở rộng FND-001 hoặc tách finding riêng; đưa các mốc vào `malware_timeline.csv`. **Liên kết với finding CB2 của Thi (FND-001(Thi/Lâm)):** response 2297 là phản hồi của request `POST /?<hex>` ở frame 2294 — đã kiểm cùng `tcp.stream 88`, `http.request_in` của 2297 = 2294. Chuỗi **2294 (POST, `09:09:22.395329Z`) → 2297 (200, body `CB2=212.117.171.138:65500`, `09:09:23.040703Z`) → 2303 (SYN tới 212.117.171.138:65500, `tcp.stream 89`, `09:09:23.086554Z`)** là cơ chế bot nhận địa chỉ CB2 qua kênh HTTP-over-6667; timeline nên thêm dòng cho frame 2294 trước 2297. Query hex 162–180 ký tự có dấu hiệu mã hóa — mức **INFERRED**, không giải mã.
5. Thêm sự kiện `GET /bd.jpg` → PE ngụy trang `image/jpeg` từ 60.190.223.75:88 (EVD-025, frame 3820 → 3895, `09:13:18.019578Z` → `09:13:19.990719Z`) vào FND-003 / timeline; cùng IP với `/sn.php` port 888 (FND-002).
6. Tuỳ chọn: thêm sự kiện finalcortex (EVD-011) và `/sn.php` mewgost.com (EVD-008) vào timeline.

### Quý (Traffic Analytics)
1. Chạy `python scripts/forensics_extract.py <pcap> --infected 147.32.84.165 --out <thư mục tạm> --zeek-dir data/processed/scenario-01-neris/zeek` để sinh `wireshark_zeek_crosscheck.csv` và xác nhận trực tiếp `match_type=1:2` cho 965/902 stream port 25/4506 (hiện mới mô phỏng, `data_consistency_check.md` §9).
2. FND-002/003(Quý): ghi rõ đơn vị "Zeek conn" và bổ sung "= 965/902 lần thử (TCP stream, 3 SYN mỗi lần)". Mean inter-arrival 8.659 s của 4506 tính trên Zeek conn (2 conn/stream) — nếu tính theo stream sẽ khác; nên tính lại theo đơn vị đã chọn.
3. Kiểm tra lại các thống kê dựa trên packet/byte: ≈ 30 % gói là bản sao capture (EVD-023). `orig_ip_bytes` của Zeek (277 920 = 5 790 × 48) đã gồm bản sao.
4. T1105: cặp `/p/out/kp.exe` (frame 251/60954) có **cùng SHA-256 body** `739bbb20…` ⇒ cùng một file tải 2 lần; danh sách 16 response + hash ở `http_pe_responses.csv`.
5. Trường hợp sport 2275 (EVD-012): PCAP có 2 stream độc lập (3405, 4302), mỗi stream bắt tay + FIN đủ; xác nhận lý giải 1 Argus flow ↔ 2 Zeek conn.
6. Tuỳ chọn: kênh nhị phân 213.246.53.125:5296, 184.154.132.106:9541, 78.129.163.119:6251, 78.129.227.128:5231 (NF-05) — volume lớn nhất PCAP, chưa có trong phân tích.
7. **Detector dựa trên nhãn giao thức/port sẽ phân loại sai luồng này.** 31 request HTTP trên port 6667 bị Wireshark/TShark gán `IRC` và 1 request HTTP trên port 88 bị gán `KRB5`; TShark mặc định chỉ đếm 1 361/1 393 HTTP request. Mọi rule/feature kiểu "port 6667 ⇒ IRC", "`-Y irc`", "`-Y http`" hoặc dựa vào cột Protocol sẽ (a) báo IRC giả, (b) bỏ sót 32 request C2/tải PE. Dùng cột `detection`/`wireshark_label` trong `http_requests.csv`; khi đối chiếu Zeek, kiểm tra cột `service` của `conn.log` cho 31 stream này (Zeek nhận dạng bằng DPD nên có thể ra `http` — cần xác nhận trên log thật).

### Lâm (Validation / Threat Intel)
1. Duyệt bảng ánh xạ FND (§2) và cấp số chính thức cho NF-01..NF-07.
2. Duyệt danh sách EVD-006..EVD-025 (§3) — xác nhận không trùng.
3. Cập nhật IOC theo §4 (đặc biệt `nomcom.com` → `nocomcom.com`).
4. Xét ATT&CK: T1090 (Proxy) cho kênh SOCKS5 65500 (EVD-007) thay/ bổ sung T1095; T1571 + T1071.001 cho HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) (EVD-024); T1036.008 (Masquerade File Type) cho `/bd.jpg` (EVD-025); xem lại mục "IRC Protocol" và "quét NetBIOS/SMB 139/445" trong `ground_truth_notes.md` §6 (EVD-020, EVD-022).
5. Quyết định xử lý lịch sử git: bản `analysis/network-forensics/S01/irc_smtp_activity.csv` đã merge qua PR #3/#7 chứa **địa chỉ email đầy đủ** trong cột `detail` (296 dòng có `@`). Bản mới đã che; bản cũ vẫn nằm trong history.
6. Ứng viên C2 mới **NF-07 — kênh HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)** (EVD-024): duyệt, cấp số FND và các IOC đề xuất ở §4 (17 IP đích; IOC-001 hiện chỉ có 200.171.4.222).

## 2. Đề xuất ánh xạ Finding ID (chờ Lâm duyệt — chưa đánh số lại)

| Nhãn tạm | Nội dung | ID hiện có | Đề xuất |
|---|---|---|---|
| FND-001(Thi/Lâm) | CB2 endpoint handover | `reports/week1/thi`, `lam` | giữ, hoặc đổi thành FND-004 nếu nhóm chọn giữ bộ của Quý |
| FND-002(Thi/Lâm) | `/sn.php` check-in | như trên | giữ / FND-005 |
| FND-003(Thi/Lâm) | Tải PE qua HTTP | như trên | giữ / FND-006 |
| FND-001(Quý) | HTTP POST finalcortex.com | `evidence/findings/FND-001.md` | giữ / FND-007 |
| FND-002(Quý) | SYN lặp port 25 (209.85.225.27) | `evidence/findings/FND-002.md` | nên gộp vào NF-02 (spam) |
| FND-003(Quý) | SYN lặp port 4506 | `evidence/findings/FND-003.md` | giữ / FND-008 |
| NF-01 (mới) | Kênh SOCKS5 ngược 212.117.171.138:65500 điều khiển SMTP/webmail | — | FND mới |
| NF-02 (mới) | Spam SMTP AUTH port 587 + SYN port 25 hàng loạt | — | FND mới |
| NF-03 (mới) | Tự phân giải MX trực tiếp tới DNS ngoài (78.3 % query) | — | FND mới |
| NF-04 (mới) | Không có IRC; HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) (đính chính dữ liệu, OBSERVED) | — | ghi chú, không cần FND |
| NF-05 (mới) | Kênh nhị phân XOR-like port 5296/9541/6251/5231/65520 | — | FND mới (Under investigation) |
| NF-06 (mới) | Baseline lành tính: Google Update, WPAD, SMB browser | — | ghi chú benign |
| NF-07 (mới) | Kênh HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port): 31 POST `/?<hex>` tới 17 IP, trả endpoint SOCKS5 — ứng viên C2 | FND-001(Thi/Lâm) chỉ phủ 1 IP | mở rộng FND-001 hoặc FND mới |

## 3. EVD mới (EVD-006 … EVD-025)

Số lớn nhất đang dùng trong repo trước khi thêm: **EVD-005** (`evidence/findings/FND-003.md`). Lưu ý: EVD-001..004 đang bị dùng **hai nghĩa** (Thi: CB2/PE; Quý: conn.log/http.log/interval/port 25) — cần Lâm chốt.

| EVD | Finding | Nội dung |
|---|---|---|
| EVD-006 | FND-001(Thi/Lâm) | CB2 response frame 2297 → SYN 2303 (45.851 ms) |
| EVD-007 | FND-001(Thi/Lâm), NF-01 | SOCKS5 CONNECT smtp.aol.com:587 (frame 3216) và relay |
| EVD-008 | FND-002(Thi/Lâm) | 16 request `/sn.php` (2 Host) |
| EVD-009 | FND-003(Thi/Lâm) | `/temp/3425.exe` frame 718/899, Host nocomcom.com, SHA-256 body |
| EVD-010 | FND-003(Thi/Lâm) | 16 response PE, 12 hash |
| EVD-011 | FND-001(Quý) | finalcortex GET + 53 POST, response `120` |
| EVD-012 | FND-001(Quý) | sport 2275 reuse (stream 3405/4302) |
| EVD-013 | FND-002(Quý) | port 25 → 965 stream / 1930 Zeek conn |
| EVD-014 | FND-003(Quý) | port 4506 → 902 stream / 1804 Zeek conn |
| EVD-015 | nhiều | Bảng DNS → connection |
| EVD-016 | NF-06 | Google Update 204 |
| EVD-017 | NF-02 | SMTP AUTH 587: 53×235 / 10×535 |
| EVD-018 | NF-03 | MX trực tiếp `.ru` (frame 13754, 77439) |
| EVD-019 | NF-06 | WPAD NXDOMAIN |
| EVD-020 | NF-06 | SMB browser tới CAMNEP-SERVER:139 |
| EVD-021 | FND-002/003(Thi/Lâm), NF-05 | port phi chuẩn |
| EVD-022 | NF-04 | HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) |
| EVD-023 | chất lượng dữ liệu | gói trùng do capture |
| EVD-024 | FND-001(Thi/Lâm), NF-07 | HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port): 31 POST tới 17 IP (frame 2294, 3341, 4556) |
| EVD-025 | FND-003(Thi/Lâm), FND-002(Thi/Lâm) | `GET /bd.jpg` port 88 (Wireshark nhận nhầm là KRB5) → PE ngụy trang `image/jpeg` (frame 3820 → 3895) |

## 4. IOC — đính chính và đề xuất (Lâm cấp ID từ IOC-015)

**Đính chính trong `reports/week1/lam/ioc_report.csv`:**

| IOC | Trường | Hiện tại | Đúng theo PCAP | Căn cứ |
|---|---|---|---|---|
| IOC-009 | ioc_value | `nomcom.com` | `nocomcom.com` | byte thô frame 718 offset 0xb0; DNS frame 195/213 |
| IOC-010 | ioc_value | `http://nomcom.com/temp/3425.exe?t=0.3419458` | `http://nocomcom.com/temp/3425.exe?t=0.3419458` | frame 718 |
| IOC-011 | ioc_value / first_seen | `http://nomcom.com/bl/client.exe` / `09:08:44.000000Z` | `http://nocomcom.com/bl/client.exe?t=0.9562799` / `2011-08-10T09:08:36.589166Z` | frame 1744 |
| IOC-012 | ioc_value / first_seen | `http://nomcom.com/sv/fjuivgfhurew.exe` / `09:09:02.000000Z` | `http://nocomcom.com/sv/fjuivgfhurew.exe?t=0.3069879` / `2011-08-10T09:09:00.057057Z` | frame 2024 |
| IOC-011/012 | category/confidence | Suspicious | có thể nâng Confirmed: response PE đủ 93 696 / 93 184 byte | frame 1918, 2241 |
| IOC-013 | description | UA cho FND-002 | đúng; UA `Mozilla` (cụt) mới là UA của POST CB2 (FND-001) | frame 2294 |

**Đề xuất IOC mới:**

| Loại | Giá trị | Liên quan | Confidence đề xuất |
|---|---|---|---|
| Domain / IPv4 | `finalcortex.com` / `31.192.109.167` | FND-001(Quý), EVD-011 | Confirmed |
| URL path | `/snapbn/gate.php`, `/snapbn/ip.php` | EVD-011 | Confirmed |
| Domain / IPv4 | `mewgost.com` / `94.63.150.20` | FND-002(Thi/Lâm), EVD-008 | Suspicious |
| Domain | `shabi.coolnuff.com`, `88.perfectexe.com` (60.190.223.75:2012/88) | EVD-010, EVD-025 | Confirmed (PE) |
| IPv4 (port 6667) | 61.17.216.4, 61.167.116.133, 61.150.114.216, 202.112.126.218, 221.207.141.60, 61.17.216.86, 211.157.110.34, 61.177.120.254, 88.250.200.14, 217.34.4.225, 218.189.208.34, 184.106.213.57, 61.17.216.94, 61.17.216.92, 60.173.109.42, 58.42.247.143 — 16 IP còn lại của kênh CB2 ngoài IOC-001 (200.171.4.222); first_seen theo `http_requests.csv` | NF-07, EVD-024 | Suspicious (nhận POST CB2; 30/31 trả endpoint C2) |
| Protocol pattern | `POST /?<hex thường, 162–180 ký tự> HTTP/1.1` + `CB2: 1` + `User-Agent: Mozilla` tới TCP 6667 — mở rộng IOC-014 | NF-07, EVD-024 | Confirmed (OBSERVED 31/31) |
| URL | `http://88.perfectexe.com:88/bd.jpg` (query `t=<số ngẫu nhiên>`) | EVD-025 | Confirmed (PE ngụy trang JPEG) |
| SHA-256 (HTTP body) | `76d3d7c35ca21b967c9dcf0125300f56ec74e00e6a3d0a90ff0aa8659b2e3b2b` (`/bd.jpg`, 55 808 B) | EVD-025 | Confirmed (hash body quan sát) |
| IPv4 — cập nhật IOC-004 | `60.190.223.75`: ngoài `/sn.php` port 888 còn phân phối PE trên port 2012 và 88 → nên đổi category sang đa vai trò (C2 check-in + payload delivery) | EVD-008, EVD-025 | Confirmed |
| Domain / IPv4 | `ii.ebatmoyhuy.com` / `94.63.149.152`; `hn.yigeyuming.com` / `122.224.6.164:82`; `61.147.99.179:81` | EVD-010 | Confirmed (PE) |
| SHA-256 (HTTP body) | 12 giá trị trong `http_pe_responses.csv` (vd. `2ed4a4ad94c6148b013aecacae783748d51d429de4f1d477a79bbf025d03d47a` = `/temp/3425.exe`) | EVD-009/010 | Confirmed (là hash body quan sát, chưa đối chiếu VirusTotal) |
| IPv4:port | `212.117.174.7:4506` | FND-003(Quý), EVD-014 | Suspicious |
| IPv4:port | `213.246.53.125:5296`, `184.154.132.106:9541` | NF-05, EVD-021 | Suspicious |
| User-Agent | `ClickAdsByIE 0.9.10` (360 request tới `1.95622.com`/`a.95622.com` `/p6.asp`) | click-fraud (README) | Suspicious |
| Protocol pattern | byte `7e` + SOCKS5 `05 02 00 02` từ server port 65500 | NF-01, EVD-007 | Confirmed |

## 5. Sai lệch phát hiện trong file của thành viên khác

| # | File | Nội dung hiện tại | Quan sát PCAP | Mức ảnh hưởng |
|---|---|---|---|---|
| 1 | `reports/week1/thi/behavior_evidence.md` §4.1; `reports/week1/lam/validation_report.md` §3.3; `ioc_report.csv`; `attack_mapping.md` §3.2 | Host `nomcom.com` | `nocomcom.com` | Cao (IOC sai) |
| 2 | `reports/week1/lam/validation_report.md` §3.3 | frame 718 `HTTP/1.1` | `HTTP/1.0` | Thấp |
| 3 | `reports/week1/thi/behavior_evidence.md` §1.1, `lam/ground_truth_notes.md` §6, `lam/dataset_manifest.csv` (`target_behaviors` có "IRC") | có IRC (61 packet) / "IRC Protocol" | không có lệnh IRC (0 NICK/USER/JOIN/PRIVMSG); 61 packet là HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) — mức OBSERVED | Trung bình |
| 4 | `reports/week1/lam/ground_truth_notes.md` §6 | "Thời gian bắt đầu 11:10:48 CEST (09:10:48 UTC)" | packet đầu `09:01:40.475792Z`; hoạt động đầu của bot `09:04:23.241037Z` | Trung bình |
| 5 | `reports/week1/lam/ground_truth_notes.md` §6 | "quét cổng NetBIOS/SMB (TCP 139, 445)" | 6 phiên SMB browser tới 1 host (147.32.84.171:139), 0 tới 445 | Trung bình |
| 6 | `reports/week1/thi/behavior_evidence.md` §4.1 | 1744/2024 "chưa phân tích response" | đều 200 OK + PE đủ (frame 1918, 2241) | Thấp (bổ sung) |
| 7 | `reports/week1/thi/behavior_evidence.md` §2.1; `lam/attack_mapping.md` T1095 | frame 3204 "server gửi dữ liệu TCP"; "Raw TCP Channel" | SOCKS5 (byte `7e`, `05 02 00 02`, CONNECT) | Trung bình |
| 8 | `reports/week2/quy/t1105_evidence_review.md` | không suy ra được 2 response `/kp.exe` giống nhau | cùng SHA-256 body `739bbb20…` | Thấp |
| 9 | `evidence/findings/FND-001.md` (Quý) | "SHA-256 cần kiểm tra lại trên Ubuntu" | khớp (đã tính lại 2026-11-16) | Thấp |
| 10 | `evidence/findings/FND-002.md`, `FND-003.md` (Quý) | 1 930 / 1 804 "connection attempts" | 965 / 902 lần thử (stream); Zeek tách 2 conn/stream | Trung bình (đơn vị) |
| 11 | ID | EVD-001..004 dùng 2 nghĩa (Thi vs Quý); FND-001..003 dùng 2 nghĩa | — | Cao (truy vết) |
| 12 | `analysis/network-forensics/S01/irc_smtp_activity.csv` (bản cũ của chính Thương, đã merge) | cột `detail` có email đầy đủ | đã che trong bản mới; history git còn | Cao (riêng tư) |
| 13 | `reports/week1/lam/ioc_report.csv` IOC-001/IOC-004; FND-001(Thi/Lâm) | kênh CB2 chỉ có 200.171.4.222; 60.190.223.75 chỉ là HTTP C2 `/sn.php` | CB2 trên port 6667 có 17 IP (31 POST, EVD-024); 60.190.223.75 còn phát tán PE trên port 88 (`/bd.jpg`, EVD-025) và 2012 | Trung bình (thiếu IOC) |

Các mục **đã kiểm và khớp**: 8 dòng `reports/week1/thi/malware_timeline.csv` (frame, ts UTC, relative, stream); số 45.85 ms; Content-Length 28 160; SHA-256 PCAP trong mọi file; `packet_count=323154` và `capture_duration=04:47:48` trong manifest của Lâm; số liệu finalcortex 54/53 và `ts` Zeek `09:08:46.277098` (= SYN frame 1867) của Quý; 16 request `/sn.php` (Quý tuần 2).

## 6. Khác biệt `datasets/dataset_manifest.csv` (Thương) và `reports/week1/lam/dataset_manifest.csv` (Lâm)

| Mục | Thương | Lâm |
|---|---|---|
| Schema | `scenario,capture,file,size_bytes,sha256,source_url,downloaded_by,date` | `scenario_id,botnet_name,…,packet_count,pcap_sha256,…,capture_duration,target_behaviors,source_url` |
| Scenario ID | `S01` | `Scenario-01` |
| Kích thước | `58266506` (byte) | `58` (MB) — khớp |
| SHA-256 | `b89c…6a36` | `b89c…6a36` — khớp |
| Nguồn | `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/` (trang tải file) | `https://www.stratosphereips.org/datasets-ctu13` (trang giới thiệu) |
| Ngày | `2026-11-12` (đã sửa từ `11/12/2026`, bỏ BOM) | không có |
| Đường dẫn PCAP | `datasets/scenario-01-neris/pcap/` | README nhóm: `data/raw/scenario-01-neris/pcap/` |

Đề xuất: nhóm thống nhất một manifest (schema của Lâm + `size_bytes`, `download_url`, `date`) và một đường dẫn PCAP; script của Thương chấp nhận cả hai đường dẫn.
