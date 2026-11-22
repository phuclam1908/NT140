# Packet Evidence — S01 (CTU-13 Scenario 1 / Neris)

| Mục | Giá trị |
|---|---|
| PCAP | `botnet-capture-20110810-neris.pcap` |
| SHA-256 | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` (kiểm tra lại 2026-11-16) |
| Công cụ | TShark/Wireshark 4.6.9 (`tshark --version`); output tái lập bằng [`REPRODUCE.md`](REPRODUCE.md) |
| Người phụ trách | Thương — Network Forensics |
| Quy ước thời gian | UTC ISO 8601 microsecond + relative (giây từ frame 1 = `2011-08-10T09:01:40.475792Z`). Wireshark: View → Time Display Format → **UTC Date and Time of Day**. |
| Biến dùng trong lệnh | `T=tshark` (Windows: `"C:\Program Files\Wireshark\tshark.exe"`), `P=<đường dẫn PCAP>` |

**Quy ước.** Mức nhận định: OBSERVED / INFERRED / UNCONFIRMED. Confidence: Cao / Trung bình / Thấp. Trạng thái: Under investigation / Provisional / Validated (chỉ Lâm chuyển sang Validated). Trường "Finding" ghi rõ nguồn ID vì repo đang có **hai bộ FND-001..003 khác nhau**: `FND-00x(Quý)` trong `evidence/findings/` và `FND-00x(Thi/Lâm)` trong `reports/week1/thi|lam/`. Finding mới của Thương đặt tên tạm `NF-0x`, chờ Lâm cấp số. EVD mới bắt đầu từ **EVD-006** (lớn nhất đang dùng trong repo là EVD-005, `FND-003(Quý)`); EVD-024, EVD-025 bổ sung sau khi kiểm tra cột `detection` của `http_requests.csv` (số tiếp theo sau EVD-023).

Không có bằng chứng nào ở đây được tạo bằng cách export/mở file từ PCAP. Byte `4D 5A` và SHA-256 body lấy từ `http.file_data` của TShark, tính trong bộ nhớ (`http_pe_responses.csv`). Giá trị định danh bot bị che sau 4 ký tự; email và credential SMTP không được ghi.

## Bảng tóm tắt

| EVD | Finding | Frame chính | Stream | ts UTC (frame chính) | Src → Dst | Proto | Observation ngắn | Mức | Conf. | Trạng thái |
|---|---|---|---|---|---|---|---|---|---|---|
| EVD-006 | FND-001(Thi/Lâm) | 2294, 2297 → 2303/2305/2306 | tcp 88 → 89 | 09:09:23.040703Z | 200.171.4.222:6667 → .165:1288; .165:1289 → 212.117.171.138:65500 | HTTP-on-6667, TCP | response `CB2=212.117.171.138:65500`, SYN sau 45.851 ms | OBSERVED | Cao | Validated (Lâm) — đã kiểm lại packet |
| EVD-007 | FND-001(Thi/Lâm) phần UNCONFIRMED; NF-01 | 3204–3242 | tcp 89, 141 | 09:10:48.664913Z | 212.117.171.138:65500 ↔ .165; .165 → 64.12.175.136:587 | SOCKS5 (data), SMTP | C2 gửi SOCKS5 CONNECT `smtp.aol.com:587`, bot mở kết nối và chuyển tiếp banner/EHLO trong < 0.4 ms | OBSERVED + INFERRED | Cao (observed) / Trung bình (vai trò) | Provisional |
| EVD-008 | FND-002(Thi/Lâm) | 4491/4495; 1702, 1727, 1937 | tcp 208; 58, 62, 67 | 09:13:36.790287Z | .165 → 60.190.223.75:888; .165 → 94.63.150.20:80 | HTTP | 16 GET `/sn.php?c=<hex ~300>` tới 2 Host | OBSERVED | Cao | Provisional (Lâm) |
| EVD-009 | FND-003(Thi/Lâm) | 718 → 899 | tcp 13 | 09:06:55.810698Z | .165 → 195.88.191.59:80 | HTTP | GET `/temp/3425.exe`, **Host `nocomcom.com`**, body 28 160 B bắt đầu `4D 5A` | OBSERVED | Cao | Validated (Lâm) — cần đính chính Host |
| EVD-010 | FND-003(Thi/Lâm) | 1744→1918, 2024→2241 (+14) | tcp 63, 81 | 09:08:36.589166Z | .165 → 195.88.191.59:80 | HTTP | 16 response body `MZ` (12 SHA-256 khác nhau) | OBSERVED | Cao | Provisional |
| EVD-011 | FND-001(Quý) | 1872/1875; 1959/1962 … 137134 | tcp 65, 70 … 6089 | 09:08:46.353691Z | .165 → 31.192.109.167:80 | HTTP | 1 GET `/snapbn/ip.php` + 53 POST `/snapbn/gate.php`, response luôn `120` | OBSERVED + INFERRED | Cao | Provisional |
| EVD-012 | FND-001(Quý) | 63221, 81158 | tcp 3405, 4302 | 10:12:54.127346Z | .165:2275 → 31.192.109.167:80 | TCP/HTTP | sport 2275 dùng lại: 2 stream riêng, mỗi stream bắt tay + FIN đủ | OBSERVED | Cao | Provisional |
| EVD-013 | FND-002(Quý) | 6502–6584 | tcp 406 | 09:17:58.456138Z | .165:1566 → 209.85.225.27:25 | TCP | 965 stream × 3 SYN (+3 s, +6 s), 0 phản hồi; Zeek 1930 = 2 × 965 | OBSERVED + INFERRED | Cao | Provisional |
| EVD-014 | FND-003(Quý) | 16488–16573 | tcp 986 | 09:28:00.380446Z | .165:2147 → 212.117.174.7:4506 | TCP | 902 stream × 3 SYN, 0 phản hồi; Zeek 1804 = 2 × 902 | OBSERVED + INFERRED | Cao | Provisional |
| EVD-015 | FND-001/002/003(Thi/Lâm), FND-001(Quý) | 195/213, 259/261, 637/643, 1837/1866 | udp | 09:06:39.924935Z | .165 → 147.32.80.9:53 | DNS | DNS → kết nối cho mọi HTTP Host (`dns_to_connection.csv`) | OBSERVED | Cao | Provisional |
| EVD-016 | NF-06 (baseline) | 37–50 | udp 1, tcp 0 | 09:04:26.691683Z | .165 → 74.125.232.195:80 | HTTP | Google Update `/service/check2` → 204 | OBSERVED | Cao | Provisional (benign) |
| EVD-017 | NF-02 | 3237–3277; 3755, 3774 | tcp 141, 194 | 09:10:49.903044Z | .165 → AOL :587 | SMTP | 64 phiên 587, 63 AUTH LOGIN: 53×235, 10×535; 53 DATA | OBSERVED | Cao | Provisional |
| EVD-018 | NF-03 | 13754; 77439 | udp 10; udp 59 | 09:26:55.398251Z | .165 → 192.33.4.12:53; 192.93.0.4 → .165 | DNS | 33 396 query (78.3 %) gửi thẳng DNS ngoài, chủ yếu MX `.ru` | OBSERVED | Cao | Provisional |
| EVD-019 | NF-06 (baseline) | 22–24 (+25–30 NBNS) | udp 1 | 09:04:24.405753Z | .165 → 147.32.80.9:53 | DNS/NBNS | `wpad` → NXDOMAIN | OBSERVED | Cao | Provisional (benign) |
| EVD-020 | NF-06 (baseline) | 491–512 | tcp 7 | 09:06:51.549292Z | .165:1046 → 147.32.84.171:139 | NBSS/SMB | phiên SMB tới CAMNEP-SERVER, NetServerEnum2; 6 lần, 1 host nội bộ | OBSERVED | Cao | Provisional (benign) |
| EVD-021 | FND-002/003(Thi/Lâm), NF-05 | 95, 166, 262, 285, 640, 3815, 4586, 21481 | tcp 1,3,5,6,11,196,215,1246 | 09:06:23.148755Z | .165 → nhiều IP | HTTP/TCP | port phi chuẩn 65520, 2012, 888, 82, 81, 88, 9541, 5296 | OBSERVED | Cao (observed) / Thấp (vai trò) | Under investigation |
| EVD-022 | NF-04 (chất lượng dữ liệu) | 2294, 2297 (61 packet) | 31 stream port 6667 | 09:09:22.395329Z | .165 → ×:6667 | HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) | Không có IRC: 0 lệnh NICK/USER/JOIN/PRIVMSG | OBSERVED | Cao | Provisional |
| EVD-023 | Chất lượng dữ liệu | 6502/6503, 22718/22807 | tcp 406, 1299 | 09:17:58.456138Z | .165 → * | — | ≈ 97 742 gói là bản sao capture (cùng `ip.id`) | OBSERVED | Cao | Provisional |
| EVD-024 | FND-001(Thi/Lâm); đề xuất NF-07 | 2294 → 2297 → 2303; 3341, 4556 (+28) | tcp 88, 150, 212 (31 stream) | 09:09:22.395329Z | .165 → 17 IP :6667 | HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) | 31 POST `/?<hex 162–180>` tới 17 IP trong 4 h 37 m; 30 response `CB2=212.117.171.138:65500` | OBSERVED (kênh) / INFERRED (query mã hóa) | Cao / Trung bình | Provisional |
| EVD-025 | FND-003(Thi/Lâm); FND-002(Thi/Lâm) (cùng IP) | 3820 → 3895 | tcp 196 | 09:13:18.019578Z | .165:1381 → 60.190.223.75:88 | HTTP trên port 88 (Wireshark nhận nhầm là KRB5) | GET `/bd.jpg` trả `image/jpeg` nhưng body 55 808 B bắt đầu `4D 5A` | OBSERVED | Cao | Provisional |

---

## EVD-006 — CB2: HTTP response trên port 6667 chỉ định endpoint, bot kết nối sau 45.851 ms

| Trường | Giá trị |
|---|---|
| Finding | FND-001(Thi/Lâm) — kiểm chứng lại packet-level (EVD-001/EVD-002 của Thi) |
| Frame(s) | 2289 (SYN), **2294** (POST), **2297** (response), **2303** (SYN), **2305** (SYN/ACK), **2306** (ACK) |
| Stream | `tcp.stream 88` (2289–2308) → `tcp.stream 89` (2303–3288) |
| Thời gian | 2294: `2011-08-10T09:09:22.395329Z` / 461.919537 · 2297: `09:09:23.040703Z` / 462.564911 · 2303: `09:09:23.086554Z` / 462.610762 · 2305: `09:09:23.109031Z` / 462.633239 · 2306: `09:09:23.109336Z` / 462.633544 |
| Src → Dst | 147.32.84.165:1288 ↔ 200.171.4.222:6667; 147.32.84.165:1289 → 212.117.171.138:65500 |
| Protocol | HTTP/1.1 — HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) → TCP |
| Display filter | `tcp.stream in {88 89} && frame.number <= 2308` (Decode As: TCP port 6667 → HTTP) |
| Lệnh tái lập | `$T -r $P -n -d tcp.port==6667,http -Y "frame.number in {2294,2297,2303,2305,2306}" -T fields -e frame.number -e frame.time_epoch -e frame.time_relative -e tcp.stream -e tcp.flags.str -e http.request.method -e http.response.code -e http.request_in` (2297 → `request_in` = 2294; 2294/2297 cùng stream 88)<br>`$T -r $P -n -d tcp.port==6667,http -Y "frame.number==2297" -T fields -e http.file_data` → hex của `CB2=212.117.171.138:65500\n` |

**Observation.** Frame 2294: `POST /?da84...[len=162] HTTP/1.1`, header `CB2: 1`, `User-Agent: Mozilla`, `Host: 200.171.4.222`. Frame 2297: `HTTP/1.1 200 OK`, Content-Length 26, body đúng 26 byte `CB2=212.117.171.138:65500\n`. Frame 2303 là SYN đầu tiên của stream 89 tới đúng IP:port đó; 2305 SYN/ACK; 2306 ACK. Δt(2297→2303) = 462.610762 − 462.564911 = **0.045851 s**. **Chuỗi 2294 → 2297 → 2303** đã kiểm: 2294 và 2297 cùng `tcp.stream 88` (147.32.84.165:1288 ↔ 200.171.4.222:6667), `http.request_in` của 2297 = **2294**; 2303 mở `tcp.stream 89` tới đúng `212.117.171.138:65500` nêu trong body của 2297. Request 2294 chính là request đầu tiên của kênh HTTP-over-6667 (EVD-024) ⇒ bot **nhận địa chỉ CB2 qua kênh HTTP trên port 6667** rồi kết nối ngay. Stream 88 kết thúc FIN (`EST_FIN`), stream 89 kéo dài tới frame 3288 (`EST_FIN`, 87.4 s). Trong PCAP có 31 POST CB2 tương tự tới 17 IP port 6667 (09:09:22Z → 13:46:46Z), 30 trả 200 — tổng hợp ở EVD-024.

**Interpretation.** Phản hồi HTTP cung cấp endpoint và bot dùng nó ngay ở tốc độ máy ⇒ cơ chế chỉ định endpoint C2 (khớp nhận định của Thi/Lâm). Các số liệu Thi/Lâm ghi (frame, relative time, 45.85 ms, stream 88/89) **đúng**.

**Lành tính / giới hạn.** Không có lý do lành tính cho POST với URI hex tới port 6667 kèm header tùy biến. URI hex chưa giải mã. Vai trò của 65500 xem EVD-007.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Validated (Lâm, giữ nguyên).

## EVD-007 — Kênh 65500 là SOCKS5 ngược: C2 điều khiển bot mở kết nối SMTP tới AOL

| Trường | Giá trị |
|---|---|
| Finding | Phần "UNCONFIRMED" của FND-001(Thi/Lâm) (vai trò 212.117.171.138:65500); đề xuất finding mới **NF-01** |
| Frame(s) | 3204, 3212, 3213, 3216, 3227, 3238, 3241 (stream 89); 3222, 3224, 3237, 3242 (stream 141) |
| Stream | `tcp.stream 89` (kênh C2) và `tcp.stream 141` (bot → 64.12.175.136:587) |
| Thời gian | 3204 `09:10:48.490976Z`/548.015184 · 3212 `09:10:48.621817Z`/548.146025 · 3213 `09:10:48.622149Z`/548.146357 · 3216 `09:10:48.664913Z`/548.189121 · 3222 `09:10:48.913315Z`/548.437523 · 3224 `09:10:49.030991Z`/548.555199 · 3227 `09:10:49.031522Z`/548.555730 · 3237 `09:10:49.702923Z`/549.227131 · 3238 `09:10:49.703250Z`/549.227458 · 3241 `09:10:49.745409Z`/549.269617 · 3242 `09:10:49.745721Z`/549.269929 |
| Src → Dst | 212.117.171.138:65500 ↔ 147.32.84.165:1289; 147.32.84.165:1337 → 64.12.175.136:587 |
| Protocol | TCP payload nhị phân (TShark: `data`) theo cấu trúc SOCKS5 (RFC 1928); SMTP |
| Display filter | `(tcp.stream == 89 || tcp.stream == 141) && tcp.len > 0 && !tcp.analysis.retransmission && frame.number <= 3242` |
| Lệnh tái lập | `$T -r $P -n -Y "tcp.stream==89 && tcp.len>0 && !tcp.analysis.retransmission" -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.len -e tcp.payload` (xem 5 dòng đầu)<br>`$T -r $P -n -Y "tcp.srcport==65500 && tcp.payload[0:3]==05:01:00 && !tcp.analysis.retransmission" -T fields -e frame.number -e tcp.payload` |

**Observation.**
| Frame | Chiều | Payload | Ý nghĩa theo RFC 1928 |
|---|---|---|---|
| 3204 | C2 → bot | `7e` (1 byte) | không thuộc SOCKS5 (byte đánh dấu riêng) |
| 3212 | C2 → bot | `05 02 00 02` | greeting: SOCKS v5, 2 method (no-auth, user/pass) |
| 3213 | bot → C2 | `05 00` | bot chọn no-auth ⇒ **bot đóng vai SOCKS server** |
| 3216 | C2 → bot | `05 01 00 03 0c "smtp.aol.com" 02 4b` | CONNECT tới domain `smtp.aol.com` port 0x024b = **587** |
| 3222/3224 | bot ↔ 64.12.175.136:587 | SYN / SYN-ACK (stream 141) | bot mở kết nối mới 248.4 ms sau lệnh CONNECT |
| 3227 | bot → C2 | `05 00 00 01 …02 4b` | reply "succeeded", 0.53 ms sau SYN-ACK 3224 |
| 3237 → 3238 | AOL → bot → C2 | banner `220-mtaout-mb05…` (422 byte) | chuyển tiếp sau **0.327 ms** |
| 3241 → 3242 | C2 → bot → AOL | lệnh `EHLO …` (21 byte, tên host đã che) | chuyển tiếp sau **0.312 ms** |

Trên toàn PCAP: 321/321 stream tới 212.117.171.138:65500 bắt tay thành công; 313 stream bắt đầu bằng `7e`; 201 lệnh CONNECT tới 46 đích khác nhau, nhiều nhất `smtp.aol.com:587` (68), `65.55.196.251:443` (29), `65.55.16.187:443` (14), `login.live.com:443` (10), `smtp.mail.yahoo.com:587` (4), MX Yahoo/AOL port 25 (7); theo port: 443 ×74, 587 ×72, 25 ×32, 80 ×23. 10 HTTP request đi **vào** máy nhiễm trong kênh này (ví dụ frame 148243 `GET mail.aol.com/`) và được bot chuyển ra ngoài (frame 148244, không có DNS trong PCAP — C2 đã phân giải).

**Interpretation (INFERRED).** 212.117.171.138:65500 là máy chủ điều khiển dùng bot như **proxy SOCKS5 ngược**: C2 quyết định đích, bot kết nối hộ và chuyển tiếp dữ liệu. Các phiên SMTP AUTH trên 587 (EVD-017) và truy cập webmail/Hotmail qua bot là lưu lượng **do C2 điều khiển**, mang IP của nạn nhân. Điều này trả lời phần "chưa rõ payload trên cổng 65500" trong báo cáo Thi/Lâm.

**Lành tính / giới hạn.** Không có ứng dụng hợp lệ nào trên máy trạm XP mở SOCKS server ngược ra port 65500. Byte `7e` và một số stream không theo mẫu (3 stream gửi dữ liệu ngẫu nhiên sau greeting) chưa giải thích. Không thấy được nội dung TLS bên trong.

**Mức:** OBSERVED (cấu trúc byte, thời gian) + INFERRED (vai trò proxy) · **Confidence:** Cao / Trung bình · **Trạng thái:** Provisional — đề nghị Thi đưa vào timeline, Lâm xét ATT&CK T1090 (Proxy).

## EVD-008 — `/sn.php` với tham số `c` hex dài (16 request, 2 Host)

| Trường | Giá trị |
|---|---|
| Finding | FND-002(Thi/Lâm) (EVD-003 của Thi) |
| Frame(s) | **4491** (GET) / **4495** (200 OK) — và 15 request khác ở bảng dưới; danh sách đầy đủ `sn_php_requests.csv` |
| Stream | `tcp.stream 208` (4486–4509, `EST_FIN`) |
| Thời gian | 4491 `2011-08-10T09:13:36.790287Z` / 716.314495 · 4495 `09:13:37.119331Z` / 716.643539 |
| Src → Dst | 147.32.84.165:1391 → 60.190.223.75:888 |
| Protocol | HTTP/1.1 |
| Display filter | `http.request.uri contains "/sn.php"` |
| Lệnh tái lập | `$T -r $P -n -Y 'http.request.uri contains "/sn.php"' -T fields -e frame.number -e frame.time_relative -e tcp.stream -e ip.dst -e tcp.dstport -e http.host` |

| Frame (req→resp) | ts UTC | Stream | Đích | Host | len(`c`) | Status |
|---|---|---|---|---|---|---|
| 541→559 | 09:06:51.928362Z | 8 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 298 | 200 |
| 625→630 | 09:06:53.281747Z | 9 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 306 | 200 |
| 758→772 | 09:06:57.258958Z | 14 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 302 | 200 |
| 857→862 | 09:06:58.630623Z | 16 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 306 | 200 |
| 914→917 | 09:07:02.124421Z | 21 | 94.63.150.20:80 | mewgost.com | 302 | 200 |
| 943→946 | 09:07:13.032350Z | 22 | 94.63.150.20:80 | mewgost.com | 306 | 200 |
| **1702**→1705 | 09:08:26.796974Z | 58 | 94.63.150.20:80 | mewgost.com | 305 | 200 |
| **1727**→1730 | 09:08:35.592272Z | 62 | 94.63.150.20:80 | mewgost.com | 306 | 200 |
| **1937**→1940 | 09:08:48.273055Z | 67 | 94.63.150.20:80 | mewgost.com | 302 | 200 |
| 2007→2010 | 09:08:59.214473Z | 80 | 94.63.150.20:80 | mewgost.com | 306 | 200 |
| 2251→2254 | 09:09:14.919795Z | 83 | 94.63.150.20:80 | mewgost.com | 297 | 200 |
| 2267→2270 | 09:09:15.347247Z | 84 | 94.63.150.20:80 | mewgost.com | 306 | 200 |
| 4123→4127 | 09:13:30.944354Z | 204 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 302 | 200 |
| 4140→4144 | 09:13:32.325082Z | 205 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 306 | 200 |
| **4491**→4495 | 09:13:36.790287Z | 208 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 302 | 200 |
| 4519→4525 | 09:13:37.726494Z | 209 | 60.190.223.75:888 | w.nucleardiscover.com:888 | 306 | 200 |

**Observation.** 16 request `GET /sn.php?c=<chuỗi hex, 297–306 ký tự>` (ví dụ 4491: `c=ECF2...[len=302]`), UA `Mozilla/4.0 (compatible; MSIE 6.0.2900.2180; Windows NT 5.1.2600)`; 8 tới mỗi Host; tất cả 200 OK; toàn bộ trong 09:06:51Z–09:13:37Z (≈ 6.8 phút), đi theo cặp cách nhau 0.4–11 s. Response từ 94.63.150.20 có Content-Length 1–2 byte. DNS: `w.nucleardiscover.com` frame 259→261, `mewgost.com` frame 637→643 (EVD-015).

**Interpretation.** Khớp số liệu Zeek của Quý (16 request, 2 nhóm). Cấu trúc là check-in tự động; **không** đủ dữ liệu cho beaconing định kỳ (chỉ 8 điểm/nhóm trong 7 phút, cặp request gần nhau).

**Lành tính / giới hạn.** Tham số `c` chưa giải mã; không chứng minh được exfiltration.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional (Lâm).

## EVD-009 — Tải PE `/temp/3425.exe` (Host thực tế là `nocomcom.com`)

| Trường | Giá trị |
|---|---|
| Finding | FND-003(Thi/Lâm) (EVD-004 của Thi) |
| Frame(s) | **718** (GET), **899** (200 OK, segment cuối + FIN) |
| Stream | `tcp.stream 13` (692–924, `EST_FIN`) |
| Thời gian | 718 `2011-08-10T09:06:55.810698Z` / 315.334906 · 899 `09:07:01.706830Z` / 321.231038 |
| Src → Dst | 147.32.84.165:1052 → 195.88.191.59:80 |
| Protocol | HTTP/1.0 request, HTTP/1.1 response |
| Display filter | `tcp.stream == 13 && http` |
| Lệnh tái lập | `$T -r $P -n -Y "frame.number==718" -x` (offset 0xb0: `48 6f 73 74 3a 20 6e 6f 63 6f 6d 63 6f 6d 2e 63 6f 6d` = `Host: nocomcom.com`)<br>`$T -r $P -n -Y "frame.number==899" -T fields -e http.content_type -e http.content_length_header -e http.file_data \| cut -c1-120` |

**Observation.** Request `GET /temp/3425.exe?t=0.3419458 HTTP/1.0`, UA `Mozilla/4.0 (compatible; MSIE 6.0.2900.2180; Windows NT 5.1.2600)`, **`Host: nocomcom.com`** (đọc từ byte thô). Response `200 OK`, `Content-Type: application/octet-stream`, `Content-Length: 28160`; body quan sát đủ **28 160 byte**, 16 byte đầu `4d5a9000 03000000 04000000 ffff0000` (`MZ`), SHA-256 body (tính trong bộ nhớ) `2ed4a4ad94c6148b013aecacae783748d51d429de4f1d477a79bbf025d03d47a`. DNS `nocomcom.com` → 195.88.191.59 (frame 195→213, 09:06:39.924935Z). Không có query/Host `nomcom.com` nào trong PCAP.

**Interpretation.** Truyền file PE hoàn chỉnh (độ dài khớp Content-Length) từ máy chủ ngoài ⇒ phù hợp T1105 như Lâm đã map. **Đính chính:** IOC-009/010/011/012 và báo cáo Thi/Lâm ghi `nomcom.com` — sai một ký tự; giá trị đúng `nocomcom.com`. Request là HTTP/1.0 (Lâm ghi HTTP/1.1).

**Lành tính / giới hạn.** Không chứng minh file được ghi đĩa/thực thi. Không mở/thực thi file.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Validated (Lâm) — đề nghị cập nhật Host trong IOC.

## EVD-010 — Toàn bộ response PE trong PCAP (16 response, 12 hash)

| Trường | Giá trị |
|---|---|
| Finding | FND-003(Thi/Lâm); đối chiếu `reports/week2/quy/t1105_*` (Quý) |
| Frame(s) | xem bảng; đầy đủ trong `http_pe_responses.csv` |
| Display filter | `http.response && http.file_data[0:2] == 4d:5a` (Decode As 88 → HTTP để thấy frame 3895) |
| Lệnh tái lập | `$T -r $P -n -d tcp.port==88,http -Y "http.response && http.file_data[0:2]==4d:5a" -T fields -e frame.number -e http.request_in -e tcp.stream -e http.content_length_header` |

| Req → Resp | Stream | ts UTC (resp) | Host | URI (path) | Byte | 16 byte đầu | SHA-256 (16 ký tự đầu) |
|---|---|---|---|---|---:|---|---|
| 123→153 | 2 | 09:06:36.258897Z | ii.ebatmoyhuy.com | /rus.php | 25 600 | 4d5a0000 01000000 02000000 ffff0000 | 94eac895ebbb0d49 |
| 171→251 | 3 | 09:06:40.643373Z | shabi.coolnuff.com:2012 | /p/out/kp.exe | 55 808 | 4d5a9000… | 739bbb203d579a08 |
| 290→447 | 6 | — | hn.yigeyuming.com:82 | /hn.gif | 128 512 | 4d5a9000… | 2bfd57e970852c35 |
| 282→617 | 4 | — | nocomcom.com | /kx4.txt | 37 376 | 4d5a9000… | 6fbc4d506f4d4e0a |
| 649→732 | 11 | — | 61.147.99.179:81 | /gggg_r.jpg | 34 304 | 4d5a9000… | 03f2eb26d958ade7 |
| 784→840 | 15 | — | ii.ebatmoyhuy.com | /ff.exe | 44 544 | 4d5a9000… | 75be179dc3141dcf |
| **718→899** | 13 | 09:07:01.706830Z | nocomcom.com | /temp/3425.exe | 28 160 | 4d5a9000… | 2ed4a4ad94c6148b |
| 960→1644 | 23 | — | nocomcom.com | /bl/chooseee.exe | 230 912 | 4d5a9000… | 617520dbb4c29f0d |
| **1744→1918** | 63 | 09:08:47.098250Z | nocomcom.com | /bl/client.exe | 93 696 | 4d5a9000… | 6d8353efda8438bf |
| **2024→2241** | 81 | 09:09:14.472709Z | nocomcom.com | /sv/fjuivgfhurew.exe | 93 184 | 4d5a0000 90900000 … | 00f15e22ab95632f |
| 3820→3895 | 196 | — | 88.perfectexe.com:88 | /bd.jpg | 55 808 | 4d5a9000… | 76d3d7c35ca21b96 |
| 3925→4087 | 198 | — | hn.yigeyuming.com:82 | /hn.gif | 128 512 | 4d5a9000… | 2bfd57e970852c35 |
| 4159→4477 | 206 | — | 61.147.99.179:81 | /gggg_r.jpg | 34 304 | 4d5a9000… | 03f2eb26d958ade7 |
| 60613→60643 | 3253 | — | ii.ebatmoyhuy.com | /rus.php | 25 600 | 4d5a0000… | 53dbaa68860c19ef |
| 60845→60954 | 3265 | — | shabi.coolnuff.com:2012 | /p/out/kp.exe | 55 808 | 4d5a9000… | 739bbb203d579a08 |
| 61037→61407 | 3271 | 10:10:32.255543Z | nocomcom.com | /kx4.txt | 37 376 | 4d5a9000… | 6fbc4d506f4d4e0a |

(Các ô "—": ts đầy đủ có trong `http_pe_responses.csv`.)

**Observation.** Frame 1744 (`/bl/client.exe`, 09:08:36.589166Z) và 2024 (`/sv/fjuivgfhurew.exe`, 09:09:00.057057Z) **đều nhận 200 OK với body PE đầy đủ** (93 696 / 93 184 byte) — Thi ghi "chưa phân tích response", nay đã có. 16 response = 16 candidate T1105 của Quý (tuần 2). Nhiều PE được ngụy trang bằng đuôi `.jpg`, `.gif`, `.txt`, `.php`; cặp `/kp.exe` (frame 251/60954) cùng SHA-256 ⇒ **cùng một file tải 2 lần** (Quý ghi "không chứng minh giống nhau" — nay đã chứng minh bằng hash toàn body). Các hash khác nhau giữa 2 lần `/rus.php`.

**Interpretation.** Bot nhận 13 response PE (11 hash khác nhau) trong ~7 phút đầu hoạt động (09:06:36Z → 09:13:35Z), rồi 3 response nữa lúc 10:09:54Z–10:10:32Z (1 hash mới của `/rus.php`, 2 file tải lại) ⇒ tổng 12 file khác nhau — mô hình downloader/pay-per-install (INFERRED).

**Lành tính / giới hạn.** Không xác nhận thực thi; prefix `4d5a0000 9090…` của frame 2241 khác chuẩn (có thể packer) — không phân tích cấu trúc PE sâu hơn.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-011 — finalcortex.com: GET `/snapbn/ip.php` + 53 POST `/snapbn/gate.php`

| Trường | Giá trị |
|---|---|
| Finding | FND-001(Quý) (EVD-001/002/003 của Quý — nguồn Zeek) |
| Frame(s) | GET **1872**→1875 (stream 65); POST đầu **1959**→1962 (stream 70); POST cuối **137134** (stream 6089) |
| Thời gian | 1872 `2011-08-10T09:08:46.353691Z` / 425.877899 · 1875 `09:08:46.433942Z` / 425.958150 · 1959 `09:08:49.527840Z` / 429.052048 · 1962 `09:08:49.611894Z` / 429.136102 · 137134 `11:16:00.632148Z` / 8060.156356 |
| Src → Dst | 147.32.84.165 → 31.192.109.167:80 |
| Protocol | HTTP/1.0 request, HTTP/1.1 response |
| Display filter | `ip.addr == 31.192.109.167 && http` |
| Lệnh tái lập | `$T -r $P -n -Y "ip.addr==31.192.109.167 && http.request" -T fields -e frame.number -e frame.time_epoch -e tcp.stream -e http.request.method -e http.request.uri \| wc -l` → 54 |

**Observation.** 54 request trong **54 TCP stream riêng** (1 request/stream, tất cả `EST_FIN`), Host `finalcortex.com`, **không có User-Agent**. GET `/snapbn/ip.php` → body 13 byte = IP công khai của máy nhiễm. 53 POST `application/x-www-form-urlencoded`, body 62 byte (52 lần) / 56 byte (lần đầu, thiếu `done`), cấu trúc cố định: `id=SARU...[len=24]&version=1337&os=2600&s5=6906&done=` — `id` giống nhau ở cả 53 POST. **53/53 response = `120`** (3 byte, `text/plain`). Stream đầu bắt đầu SYN frame 1867 `09:08:46.277098Z` = đúng `ts` Zeek UID `C3B3Mk3fDKCLd9aoB8` của Quý.

**Interpretation (INFERRED).** `ip.php` là bước kiểm tra IP công khai; `gate.php` là check-in định kỳ gắn với một bot ID lấy từ tên máy (SARUMAN). Server trả `120` liên tục và khoảng cách POST trung vị 123.46 s (Quý) ⇒ nhiều khả năng `120` là chu kỳ (giây) do C2 chỉ định. `os=2600` trùng build Windows XP; `s5=6906` có thể là port SOCKS5 cục bộ — **UNCONFIRMED** (không thấy kết nối vào 6906 trong PCAP).

**Lành tính / giới hạn.** Không có UA, body định dạng máy ⇒ không phải duyệt web. Không giải thích được các khoảng cách dài (tới 424 s).

**Mức:** OBSERVED + INFERRED · **Confidence:** Cao · **Trạng thái:** Provisional (đủ packet evidence cho FND-001(Quý); Lâm quyết định Validated).

## EVD-012 — Source port 2275 dùng lại tới 31.192.109.167:80

| Trường | Giá trị |
|---|---|
| Finding | FND-001(Quý) — trường hợp Zeek UID `CyX70D31uZteVKQKja` không ghép Argus |
| Frame(s) | 63221–63243 (stream 3405), **81158**–81175 (stream 4302) |
| Thời gian | 63221 `2011-08-10T10:12:54.127346Z` / 4273.651554 · 81158 `10:31:25.469770Z` / 5384.993978 |
| Src → Dst | 147.32.84.165:2275 → 31.192.109.167:80 |
| Display filter | `tcp.port == 2275` |
| Lệnh tái lập | `$T -r $P -n -Y "tcp.port==2275 && tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.number -e frame.time_relative -e tcp.stream -e ip.dst -e tcp.dstport -e _ws.col.Info` |

**Observation.** sport 2275 xuất hiện ở 6 stream: 1098/1099 (94.95.56.138:6667, `REJ`, 09:29:56Z), 1100 (cùng đích, `S0`), **3405** và **4302** (31.192.109.167:80, mỗi stream có SYN + SYN/ACK + FIN hai chiều, `EST_FIN`, 15 packet, POST `/snapbn/gate.php`), 10455 (205.188.103.1:25, `S0`, 13:00:08Z). TShark gắn `[TCP Port numbers reused]` cho SYN frame 81158 và tách thành stream mới. Thời điểm 2 stream khớp đúng 2 Zeek UID (`C6eXbjsS9mQPm1IEe` 10:12:54.127346, `CyX70D31uZteVKQKja` 10:31:25.469770).

**Interpretation.** Đây là **hai kết nối TCP độc lập** (2 bắt tay, 2 lần đóng FIN) cách nhau 18.5 phút do Windows XP quay vòng ephemeral port (1024–5000). Argus gộp thành 1 flow dài 1 111.6 s (theo Quý) là đặc thù của Argus, không phải do PCAP. ⇒ Nên gán nhãn flow Argus đó cho cả 2 Zeek conn **có ghi chú 1:n**, không coi conn thứ 2 là unlabeled.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-013 — Port 25 tới 209.85.225.27: 965 stream S0, Zeek đếm 1930

| Trường | Giá trị |
|---|---|
| Finding | FND-002(Quý) (EVD-004 của Quý) |
| Frame(s) | 6502/6503, 6526/6527, 6583/6584 (stream mẫu) |
| Stream | `tcp.stream 406` (mẫu); 965 stream, xem `network_connections.csv` lọc `dst_ip=209.85.225.27` |
| Thời gian | 6502 `2011-08-10T09:17:58.456138Z` / 977.980346 · 6526 `09:18:01.460681Z` / 980.984889 · 6583 `09:18:07.469257Z` / 986.993465 |
| Src → Dst | 147.32.84.165:1566 → 209.85.225.27:25 |
| Display filter | `ip.dst == 209.85.225.27 && tcp.dstport == 25` |
| Lệnh tái lập | `$T -r $P -n -Y "ip.dst==209.85.225.27 && tcp.dstport==25" -T fields -e tcp.stream \| sort -u \| wc -l` → 965; `$T -r $P -n -Y "tcp.stream==406" -T fields -e frame.number -e frame.time_relative -e ip.id -e tcp.seq_raw` |

**Observation.** 965 stream, **mỗi stream đúng 6 packet = 3 SYN × 2 bản sao**, 3 `ip.id` khác nhau, cùng ISN (stream 406: 605998363), khoảng cách SYN +3 s rồi +6 s; **0 packet** từ 209.85.225.27 trong toàn PCAP; 965/965 `S0`. Stream đầu 09:17:58Z, cuối 13:47:49Z.

**Interpretation (INFERRED).** Zeek tách mỗi stream thành 2 conn (SYN#1+#2 / SYN#3) ⇒ 1 930 = 2 × 965; mô phỏng quy tắc "gói > start + 5 s ⇒ conn mới" cho đúng 1 930 và thời lượng TB 1.5157 s (Zeek 1.5165 s) — chi tiết `data_consistency_check.md` §9. Số "lần thử kết nối" thực = 965.

**Lành tính / giới hạn.** 209.85.225.27 là MX của Google; SYN không được trả lời có thể do lọc port 25 ở biên mạng CTU — không chứng minh bot gửi được thư.

**Mức:** OBSERVED + INFERRED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-014 — Port 4506 tới 212.117.174.7: 902 stream S0, Zeek đếm 1804

| Trường | Giá trị |
|---|---|
| Finding | FND-003(Quý) (EVD-005 của Quý) |
| Frame(s) | 16488/16489, 16530/16531, 16572/16573 (stream mẫu) |
| Stream | `tcp.stream 986` (mẫu); 902 stream |
| Thời gian | 16488 `2011-08-10T09:28:00.380446Z` / 1579.904654 · 16530 `09:28:03.384520Z` / 1582.908728 · 16572 `09:28:09.393422Z` / 1588.917630 |
| Src → Dst | 147.32.84.165:2147 → 212.117.174.7:4506 |
| Display filter | `ip.dst == 212.117.174.7 && tcp.dstport == 4506` |
| Lệnh tái lập | như EVD-013, đổi IP/port |

**Observation.** 902 stream × 6 packet (3 SYN × 2), 0 phản hồi, 902/902 `S0`, 09:28:00Z → 13:48:03Z. 212.117.174.7 cùng dải /22 với C2 SOCKS 212.117.171.138.

**Interpretation.** Như EVD-013: 1 804 Zeek conn = 2 × 902 stream. Kết nối lặp tới một C2 dự phòng không phản hồi là giả thuyết (UNCONFIRMED) — dữ liệu không có payload nào.

**Mức:** OBSERVED + INFERRED · **Confidence:** Cao (số đếm) / Thấp (vai trò) · **Trạng thái:** Provisional.

## EVD-015 — Bảng DNS → connection (yêu cầu của Lâm)

| Trường | Giá trị |
|---|---|
| Finding | FND-001/002/003(Thi/Lâm), FND-001(Quý) |
| Nguồn | `dns_to_connection.csv` (141 cặp Host–IP–port; 117 `resolved-ip-matches`, 21 Host là IP literal, 3 không có DNS trong PCAP) |
| Display filter | `dns.qry.name == "nocomcom.com"` (thay tên) |
| Lệnh tái lập | `$T -r $P -n -Y 'dns.qry.name=="nocomcom.com"' -T fields -e frame.number -e frame.time_relative -e dns.flags.response -e dns.a -e dns.response_to` |

| Host | DNS query→resp (frame) | DNS ts UTC | Resolver | Trả về | HTTP đầu (frame, stream) | SYN đầu (frame) | Δ resp→SYN |
|---|---|---|---|---|---|---|---|
| nocomcom.com | 195→213 | 09:06:39.924935Z | 147.32.80.9 | 195.88.191.59 | 282 (`/kx4.txt`), s4; **718** là request thứ 2 | 214 | 0.30 ms |
| `nomcom.com` (tên trong IOC) | **không có** query/Host nào | — | — | — | — | — | — |
| w.nucleardiscover.com | 259→261 | 09:06:41.961241Z | 147.32.80.9 | 60.190.223.75 | 267, s5 | 262 | 1.35 ms |
| mewgost.com | 637→643 | 09:06:53.711997Z | 147.32.80.9 | 94.63.150.20 | 654, s12 | 644 | 1.25 ms |
| finalcortex.com | 1837→1866 (15 query tổng) | 09:08:45.828469Z | 147.32.80.9 | 31.192.109.167 | 1872, s65 | 1867 | 0.82 ms |
| shabi.coolnuff.com | 161→165 | 09:06:37.018968Z | 147.32.80.9 | 60.190.223.75 | 171, s3 | 166 | 0.29 ms |
| 88.perfectexe.com | 3808→3814 | 09:13:15.606019Z | 147.32.80.9 | 60.190.223.75 | 3820, s196 | 3815 | 1.17 ms |
| ii.ebatmoyhuy.com | 115→117 | 09:06:35.618108Z | 147.32.80.9 | 94.63.149.152 | 123, s2 | 118 | 0.55 ms |
| hn.yigeyuming.com | 277→284 | 09:06:43.475821Z | 147.32.80.9 | 122.224.6.164 | 290, s6 | 285 | 1.19 ms |
| 200.171.4.222 (CB2) | IP literal — không cần DNS | — | — | — | 2294, s88 | 2289 | — |
| mail.aol.com, my.screenname.aol.com | không có DNS (bot nhận đích qua SOCKS) | — | — | — | 148244, s6329 | 148226 | — |

**Observation / Interpretation.** Mọi domain C2/tải file đều được phân giải qua resolver nội bộ ngay trước kết nối (SYN < 2 ms sau response). Hai domain C2 dùng chung IP 60.190.223.75 (`w.nucleardiscover.com`, `shabi.coolnuff.com`, `88.perfectexe.com`). Đích webmail không có DNS vì C2 gửi địa chỉ qua SOCKS (EVD-007).

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-016 — Google Update `/service/check2` → 204 (baseline lành tính)

| Trường | Giá trị |
|---|---|
| Finding | đề xuất NF-06 (baseline hệ điều hành/ứng dụng — dùng làm mẫu benign) |
| Frame(s) | 37/38 (DNS query + bản sao), 39 (response), 40–44 (bắt tay), **45** (GET), **48** (204), 49/50 (RST/ACK + bản sao) |
| Stream | `udp.stream 1`, `tcp.stream 0` |
| Thời gian | 37 `2011-08-10T09:04:26.661355Z` / 166.185563 · 45 `09:04:26.691683Z` / 166.215891 · 48 `09:04:26.725384Z` / 166.249592 · 50 `09:04:26.728225Z` / 166.252433 |
| Src → Dst | 147.32.84.165:1027 → 74.125.232.195:80 |
| Display filter | `frame.number >= 37 && frame.number <= 50` |
| Lệnh tái lập | `$T -r $P -n -Y "frame.number>=37 && frame.number<=50"` |

**Observation.** `GET /service/check2?appid=%7B4...[len=42]&appversion=1.3.21.65…`, UA `Google Update/1.3.21.65;winhttp`, response `HTTP/1.1 204 No Content`; client đóng bằng RST/ACK (`EST_RST`, rst_by=orig). DNS `cr-tools.clients.google.com`: 17 answer (1 CNAME + 16 A); 4 IP `216.239.3x.10` là glue của additional section (script cũ lẫn vào `answers_A`, đã sửa).

**Interpretation.** Kiểm tra cập nhật Google bình thường của Windows XP — mẫu **benign** trong PCAP botnet, hữu ích để kiểm tra false positive của rule HTTP.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional (benign).

## EVD-017 — SMTP AUTH LOGIN trên port 587 (spam qua tài khoản webmail)

| Trường | Giá trị |
|---|---|
| Finding | đề xuất NF-02; liên quan FND-002(Quý) (spam) và EVD-007 |
| Frame(s) | phiên đầu: 3237 (220), **3257** (AUTH LOGIN), **3277** (535) — stream 141; phiên 235 đầu: **3755** (235), **3774** (DATA) — stream 194 |
| Thời gian | 3257 `2011-08-10T09:10:49.903044Z` / 549.427252 · 3277 `09:10:50.416907Z` / 549.941115 · 3755 `09:13:08.754139Z` / 688.278347 · 3774 `09:13:09.227810Z` / 688.752018 |
| Src → Dst | 147.32.84.165:1337 → 64.12.175.136:587; 147.32.84.165:1379 → 205.188.186.137:587 |
| Display filter | `smtp.req.command || smtp.response.code` |
| Lệnh tái lập | `$T -r $P -n -Y "smtp.response.code==235" \| wc -l` → 53; `… ==535` → 10; `$T -r $P -n -Y "smtp.req.command" -T fields -e smtp.req.command \| sort \| uniq -c` |

**Observation.** 64 phiên SMTP (TCP stream), **100 % port 587**, 6 máy chủ AOL/Yahoo. Lệnh: EHLO 63, AUTH 63 (cơ chế LOGIN), MAIL 82, RCPT 214, DATA 81, QUIT 14. Response: **235 ×53**, **535 ×10**, 421 ×28, 554 ×6. 53 phiên có DATA (1–12 RCPT/phiên). 09:10:49Z → 13:23:14Z. Dòng username/password base64 sau `AUTH LOGIN` (126 packet `smtp.req` không có command) **không được giải mã hay ghi lại**; địa chỉ email trong `irc_smtp_activity.csv` đã che local-part.

**Interpretation.** Phiên đầu (stream 141) được mở theo lệnh SOCKS của C2 (EVD-007) ⇒ spam được gửi qua tài khoản webmail thật bằng IP nạn nhân (INFERRED). Tỷ lệ đăng nhập thành công 53/63 = 84 %.

**Lành tính / giới hạn.** Không có phiên SMTP nào khác ngoài 64 phiên 587 này và phiên đầu được mở theo lệnh SOCKS của C2 — khả năng là người dùng gửi thư hợp lệ thấp. Không xác minh được tài khoản có bị chiếm hay không; không đọc nội dung thư.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-018 — DNS MX gửi thẳng tới DNS bên ngoài (root/TLD `.ru`/authoritative)

| Trường | Giá trị |
|---|---|
| Finding | đề xuất NF-03 |
| Frame(s) | **13754**/13755 (query đầu + bản sao); **77439** (response NXDOMAIN từ 192.93.0.4); 77436–77446 (cụm mẫu) |
| Stream | `udp.stream 10` (13754); `udp.stream 59` (77439) |
| Thời gian | 13754 `2011-08-10T09:26:55.398251Z` / 1514.922459 · 77439 `10:29:05.237694Z` / 5244.761902 |
| Src → Dst | 147.32.84.165:2077 → 192.33.4.12:53; 192.93.0.4:53 → 147.32.84.165:2077 |
| Display filter | `dns && ip.dst != 147.32.80.9 && ip.src == 147.32.84.165` |
| Lệnh tái lập | `$T -r $P -n -Y "frame.number>=77436 && frame.number<=77446"` |

**Observation.** 13754: `MX hotmail.com` gửi tới 192.33.4.12 (root server C). 77439: `No such name MX metafrazor.ru`, SOA `ns.ripn.net` (máy chủ `.ru`). Cụm 77436–77446 (10:29:05Z) cho thấy bot đi tiếp tới NS authoritative (95.163.16.202, 193.232.142.17…). Tổng: 33 396/42 669 query duy nhất (78.3 %) là `external_direct`, 2 189 máy chủ, 21 367 MX, 25 853 tên `.ru`; 14 675 không có phản hồi.

**Interpretation.** Spam engine tự phân giải MX lặp (không qua resolver nội bộ) — dấu hiệu mạnh của spambot; tạo ra 1/4 số packet PCAP.

**Lành tính / giới hạn.** Máy trạm Windows không tự gửi DNS tới root server ⇒ không có giải thích lành tính hợp lý. Rule phát hiện dựa trên "DNS tới IP ngoài resolver nội bộ" sẽ cần whitelist resolver hợp lệ.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-019 — WPAD NXDOMAIN (baseline lành tính)

| Trường | Giá trị |
|---|---|
| Finding | NF-06 (baseline) |
| Frame(s) | **22**/23 (query + bản sao 6 µs), **24** (NXDOMAIN); NBNS `WPAD.<00>` 25–30 |
| Stream | `udp.stream 1` (DNS), `udp.stream 0` (NBNS) |
| Thời gian | 22 `2011-08-10T09:04:24.405753Z` / 163.929961 · 24 `09:04:24.406378Z` / 163.930586 |
| Src → Dst | 147.32.84.165:1025 → 147.32.80.9:53 |
| Display filter | `dns.qry.name == "wpad" || nbns.name contains "WPAD"` |
| Lệnh tái lập | `$T -r $P -n -Y "frame.number>=22 && frame.number<=30"` |

**Observation.** `A wpad` → `No such name` (SOA a.root-servers.net), sau đó broadcast NBNS. Frame 23 là bản sao của 22 (cùng `ip.id 0x0002`, Δt = 6 µs) — script gộp thành 1 query (`dup_frames=23`).

**Interpretation.** Tự dò proxy (WPAD) mặc định của Internet Explorer khi khởi động — benign.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional (benign).

## EVD-020 — NetBIOS/SMB tới 147.32.84.171:139 (baseline nội bộ)

| Trường | Giá trị |
|---|---|
| Finding | NF-06 (baseline); trả lời câu hỏi "quét NetBIOS/SMB" trong `ground_truth_notes.md` (Lâm) |
| Frame(s) | **491**/492 (SYN + bản sao), 493 (SYN/ACK), 494 (NBSS Session request `CAMNEP-SERVER<20>` from `SARUMAN<00>`), 498–508 (SMB Negotiate / Session Setup NTLMSSP rỗng), 509 (Tree Connect `\\CAMNEP-SERVER\IPC$`), 512 (LANMAN NetServerEnum2) |
| Stream | `tcp.stream 7` (`EST_FIN`) |
| Thời gian | 491 `2011-08-10T09:06:51.549292Z` / 311.073500 · 512 `09:06:51.564790Z` / 311.088998 |
| Src → Dst | 147.32.84.165:1046 → 147.32.84.171:139 |
| Display filter | `tcp.port == 139 || tcp.port == 445` |
| Lệnh tái lập | `$T -r $P -n -Y "tcp.dstport in {139,445} && tcp.flags.syn==1 && tcp.flags.ack==0 && !tcp.analysis.retransmission" -T fields -e frame.number -e frame.time_relative -e ip.dst -e tcp.dstport` |

**Observation.** Chỉ **6 stream** tới 139 (0 tới 445), **1 host nội bộ duy nhất** (147.32.84.171 = CAMNEP-SERVER), đều bắt tay đủ và `EST_FIN`, lặp khoảng 32 phút: frame 491 (09:06:51Z), 31262 (09:38:53Z), 61746 (10:10:57Z), 91928 (10:43:02Z), 223823 (12:19:12Z), 284724 (13:23:20Z). Nội dung là phiên null-session đọc danh sách máy chủ (Computer Browser).

**Interpretation.** Hành vi Computer Browser chuẩn của Windows XP — **không phải** quét NetBIOS/SMB. Không có bằng chứng lan truyền ngang (T1021/T1046) trong PCAP.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional (benign).

## EVD-021 — Port phi chuẩn khác (65520, 2012, 888, 82, 81, 88, 9541, 5296)

| Trường | Giá trị |
|---|---|
| Finding | FND-002/003(Thi/Lâm) (888, 2012), đề xuất NF-05 (kênh nhị phân) |
| Frame(s) / stream | 95 (s1, →60.190.222.139:65520, nhị phân), 166/171 (s3, →60.190.223.75:2012, HTTP `/p/out/kp.exe`), 262 (s5, →60.190.223.75:888, `/sn.php`), 285/290 (s6, →122.224.6.164:82, HTTP `/hn.gif` = PE), 640/649 (s11, →61.147.99.179:81, HTTP `/gggg_r.jpg` = PE), 3815/3820 (s196, →60.190.223.75:88, HTTP `/bd.jpg` = PE, TShark gán nhầm KRB5), 4580/4586 (s215, →184.154.132.106:9541), 21474/21481 (s1246, →213.246.53.125:5296) |
| Thời gian | 95 `09:06:23.148755Z`/282.672963 · 166 `09:06:38.391395Z`/297.915603 · 262 `09:06:42.509943Z`/302.034151 · 285 `09:06:44.036676Z`/303.560884 · 640 `09:06:53.910439Z`/313.434647 · 3815 `09:13:17.691742Z`/697.215950 · 4586 `09:14:07.138912Z`/746.663120 · 21481 `09:32:08.568799Z`/1828.093007 |
| Display filter | `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport in {65520 2012 888 82 81 88 9541 5296}` |
| Lệnh tái lập | `$T -r $P -n -Y "tcp.stream in {1,3,6,11,196,215,1246} && tcp.len>0" -T fields -e frame.number -e tcp.stream -e ip.src -e tcp.len -e tcp.payload \| cut -c1-80` |

**Observation.** 65520: 2 stream (60.190.222.139, 94.63.149.150), payload nhị phân. 9541/5296: server gửi trước 1 byte (`e2`/`e0`) rồi chuỗi lặp `e2e2e2e2e4…`/`e0e0e0e0e6…` (giống XOR một byte), khối lượng 2.9–3.2 MB/IP (cao nhất PCAP theo packet). 2012/82/81/88: HTTP trả PE (EVD-010). 888: `/sn.php` (EVD-008).

**Interpretation.** Port phi chuẩn ở S01 phục vụ hai mục đích: (a) HTTP tải file/check-in (đã rõ), (b) kênh nhị phân mã hóa chưa rõ chức năng (5296/9541/6251/5231/65520) — giả thuyết proxy/C2 thứ cấp, **UNCONFIRMED**.

**Mức:** OBSERVED · **Confidence:** Cao (observed) / Thấp (chức năng kênh nhị phân) · **Trạng thái:** Under investigation.

## EVD-022 — Không có IRC: HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)

| Trường | Giá trị |
|---|---|
| Finding | đề xuất NF-04 (đính chính dữ liệu); liên quan FND-001(Thi/Lâm) |
| Frame(s) | 2294/2297 (mẫu); 61 packet `irc` trong 31 stream |
| Display filter | `irc` và `tcp.payload contains "NICK " || tcp.payload contains "USER " || tcp.payload contains "JOIN #" || tcp.payload contains "PRIVMSG"` |
| Lệnh tái lập | `$T -r $P -n -Y irc \| wc -l` → 61; `$T -r $P -n -Y 'tcp.payload contains "PRIVMSG"' \| wc -l` → 0 |

**Observation.** 61/61 packet TShark mặc định đếm vào `irc` bắt đầu bằng `POST /?` hoặc `HTTP/1.1` (cột `note` trong `irc_smtp_activity.csv`), tức là HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port). Trong `http_requests.csv`, 31 request này có `detection=payload_heuristic`, `wireshark_label=IRC`. Không có lệnh IRC nào trong toàn bộ payload TCP. 1 314 stream tới port 6667 (478 IP) chủ yếu `S0`/`REJ`; 4 gói RST kèm 23 byte text (`Syn Idle expired:(…)` frame 8963; `Go away, we're not home` frame 220353/220362/220376) — không phải lệnh IRC.

**Interpretation.** Neris trong S01 dùng **port** 6667 nhưng **giao thức** HTTP (CB2). Các ghi nhận "IRC Protocol: kết nối IRC server nhận lệnh" (`ground_truth_notes.md` §6) và "IRC 61 packet" (Thi §1.1) cần đổi thành "HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)"; T1571 (Non-Standard Port) vẫn đúng, không thêm "IRC C2".

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-023 — Gói trùng do capture

| Trường | Giá trị |
|---|---|
| Finding | Chất lượng dữ liệu (ảnh hưởng mọi finding đếm packet) |
| Frame(s) | 6502/6503 (Δ 8 µs, `ip.id 0x0ad4`); 22718/22807 (Δ 0.566 s, `ip.id 0x2e22`, stream 1299) |
| Lệnh tái lập | `scripts/consistency_check.py` (bộ đếm độc lập) hoặc `$T -r $P -n -Y "tcp.stream==1299" -T fields -e frame.number -e frame.time_relative -e ip.id -e tcp.seq_raw` |

**Observation.** 97 742 gói TCP/UDP (30.2 %) là bản sao < 1 ms; thêm ~22 000 gói lặp 1 ms–2 s. 97 702/97 767 bản sao (< 1 ms, đếm theo khoá gói TCP/UDP) là gói **đi ra** từ máy nhiễm. TShark gắn cờ `tcp.analysis.retransmission` cho bản sao.

**Interpretation.** Do cách bắt gói trên interface VM (giả thuyết: gói được ghi trước và sau tầng giới hạn băng thông). Phải dùng `packets_dedup`/khử trùng khi đếm volume hoặc retransmission.

**Mức:** OBSERVED (hiện tượng) / UNCONFIRMED (nguyên nhân) · **Confidence:** Cao · **Trạng thái:** Provisional.

## EVD-024 — Kênh HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port): 31 HTTP POST tới 17 IP

| Trường | Giá trị |
|---|---|
| Finding | FND-001(Thi/Lâm) (mở rộng từ 1 IP 200.171.4.222 ra toàn kênh); đề xuất **NF-07** "kênh HTTP-over-6667 là ứng viên C2", chờ Lâm cấp số |
| Frame(s) | **2294** (đầu tiên), **3341**, **4556** (mẫu); đủ 31 frame: `http_requests.csv` lọc `detection=payload_heuristic` và `dst_port=6667` |
| Stream | `tcp.stream 88` (2294 → 2297, cùng stream; tiếp theo 2303 trên `tcp.stream 89`), `150` (3341 → 3344), `212` (4556, không phản hồi); 31 stream tổng |
| Thời gian | 2294: `2011-08-10T09:09:22.395329Z` / 461.919537 · 3341: `09:11:21.652669Z` / 581.176877 (response 3344: `09:11:22.320589Z` / 581.844797) · 4556: `09:14:05.629204Z` / 745.153412 · cuối (317491): `13:46:46.039076Z` / 17105.563284 — khoảng **4 h 37 m 23.6 s** |
| Src → Dst | 147.32.84.165 → 200.171.4.222, 61.17.216.4, 211.157.110.34 … (**17 IP khác nhau**, tất cả port 6667) |
| Protocol | HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port); TShark mặc định: `IRC` (`frame.protocols` = `eth:ethertype:ip:tcp:irc`) |
| Display filter | `tcp.dstport == 6667 && http.request` (cần Analyze → Decode As: TCP 6667 → HTTP) |
| Lệnh tái lập | `$T -r $P -n -d tcp.port==6667,http -Y "http.request && tcp.dstport==6667" -T fields -e frame.number -e frame.time_epoch -e tcp.stream -e ip.dst -e http.user_agent \| wc -l` → 31<br>`$T -r $P -n -Y "frame.number in {2294,3341,4556}" -T fields -e frame.number -e _ws.col.protocol` → `IRC` (không decode-as)<br>`$T -r $P -n -d tcp.port==6667,http -Y "http.response && tcp.srcport==6667" -T fields -e http.file_data` → 30 dòng cùng hex của `CB2=212.117.171.138:65500\n` |

**Observation.**
- 31 request `POST /?<query> HTTP/1.1`, header `CB2: 1`, `User-Agent: Mozilla` (chuỗi cụt), `Host` = IP đích, không có body (không `Content-Length`).
- **17 IP đích khác nhau**: 61.17.216.4 ×5, 61.167.116.133 ×5, 61.150.114.216 ×4, 202.112.126.218 ×2, 221.207.141.60 ×2, 61.17.216.86 ×2; mỗi IP còn lại ×1 (200.171.4.222, 211.157.110.34, 61.177.120.254, 88.250.200.14, 217.34.4.225, 218.189.208.34, 184.106.213.57, 61.17.216.94, 61.17.216.92, 60.173.109.42, 58.42.247.143).
- Khoảng cách giữa 2 POST liên tiếp: min 18.7 s, median 229.2 s, max 2 415.6 s.
- Query string: path luôn `/`, query **chỉ gồm ký tự hex thường**, dài 162–180 ký tự, **31/31 khác nhau**; entropy theo ký tự 3.3–3.7 bit (tối đa của bảng hex là 4). Giá trị đầy đủ không ghi ra (che sau 4 ký tự trong CSV).
- 30/31 có response `HTTP/1.1 200`, `Content-Type: text/html; charset=UTF-8`, Content-Length 26, body luôn `CB2=212.117.171.138:65500\n`. Frame 4556 (stream 212) không có phản hồi: bot gửi lại POST nhiều lần rồi FIN.
- Toàn bộ port 6667: 1 314 TCP stream tới 478 IP — S0 739, REJ 519, EST_FIN 31, EST_RST 8, PARTIAL 16, SYN_ACK_NO_ACK 1. Chỉ 31 stream có HTTP POST.
- Ở cấp packet: 106 packet có payload trên port 6667 = 72 `POST` (31 request duy nhất; phần còn lại là bản sao capture và gửi lại) + 30 `HTTP/1.1 200` + 4 RST kèm text của middlebox.
- TShark mặc định **không** nhận các request này là HTTP (1 361 vs 1 393): cột `detection=payload_heuristic`, `wireshark_label=IRC`.

**Chuỗi frame 2294 → 2297 → 2303 (OBSERVED, đã kiểm).** 2294 `POST /?da84...[len=162]` (`09:09:22.395329Z` / 461.919537, `tcp.stream 88`) → 2297 `HTTP/1.1 200`, body `CB2=212.117.171.138:65500` (`09:09:23.040703Z` / 462.564911, **cùng `tcp.stream 88`**, `http.request_in = 2294`) → 2303 SYN `147.32.84.165:1289 → 212.117.171.138:65500` (`09:09:23.086554Z` / 462.610762, `tcp.stream 89`, sau 45.851 ms). Response 2297 chính là bằng chứng CB2 của Thi (EVD-006, FND-001(Thi/Lâm)); nó là phản hồi cho request đầu tiên của kênh này. Đây là **cơ chế bot nhận địa chỉ CB2 qua kênh HTTP-over-6667**.

**Interpretation.** (OBSERVED) Đây là một kênh HTTP độc lập trên port 6667, không phải IRC, có chung định dạng với CB2 ở EVD-006 và luôn trả cùng một endpoint SOCKS5 (EVD-007) ⇒ bot xoay vòng nhiều dispatcher để lấy endpoint C2. (INFERRED) Query hex dài, không lặp, entropy gần tối đa của bảng hex ⇒ nhiều khả năng là dữ liệu đã **mã hóa/nén rồi hex-encode** (định danh bot/trạng thái). **Không giải mã** — chỉ ghi cấu trúc.

**Lành tính / giới hạn.** Không có dịch vụ HTTP hợp lệ nào dùng port 6667 với header `CB2`. Chưa biết vì sao 17 IP khác nhau trả cùng một endpoint (có thể là proxy/host bị chiếm quyền — UNCONFIRMED). Detector dựa trên nhãn giao thức của Wireshark/Zeek hoặc dựa trên port sẽ xếp kênh này là IRC.

**Mức:** OBSERVED (kênh, số đếm) / INFERRED (query được mã hóa) · **Confidence:** Cao / Trung bình · **Trạng thái:** Provisional.

## EVD-025 — `GET /bd.jpg` trên port 88: file PE ngụy trang JPEG từ 60.190.223.75

| Trường | Giá trị |
|---|---|
| Finding | FND-003(Thi/Lâm) (tải PE); liên quan FND-002(Thi/Lâm) vì cùng IP 60.190.223.75 với `/sn.php` port 888 (EVD-008) |
| Frame(s) | 3808/3814 (DNS `88.perfectexe.com`), 3815 (SYN), 3817 (SYN/ACK), **3820** (GET), **3895** (response cuối, reassembled), 5309 (RST từ server) |
| Stream | `tcp.stream 196` |
| Thời gian | 3808: `2011-08-10T09:13:15.606019Z` / 695.130227 · 3815: `09:13:17.691742Z` / 697.215950 · 3820: `09:13:18.019578Z` / 697.543786 · 3895: `09:13:19.990719Z` / 699.514927 · 5309: `09:15:30.977108Z` / 830.501316 |
| Src → Dst | 147.32.84.165:1381 → 60.190.223.75:88 |
| Protocol | HTTP/1.1 trên port 88 (Wireshark nhận nhầm là KRB5 theo port) |
| Display filter | `tcp.stream == 196` (Decode As: TCP 88 → HTTP) |
| Lệnh tái lập | `$T -r $P -n -d tcp.port==88,http -Y "tcp.stream==196 && http" -T fields -e frame.number -e frame.time_epoch -e http.request.uri -e http.host -e http.response.code -e http.content_type -e http.content_length_header`<br>`$T -r $P -n -Y "frame.number==3820" -T fields -e _ws.col.protocol` → `KRB5`<br>`$T -r $P -n -d tcp.port==88,http -Y "frame.number==3895" -T fields -e http.file_data \| cut -c1-32` → `4d5a9000…` (không ghi ra đĩa) |

**Observation.**
- Request: `GET /bd.jpg?t=0.9809509`, `Host: 88.perfectexe.com:88`, UA `Mozilla/4.0 (compatible; MSIE 6.0.2900.2180; Windows NT 5.1.2600)` (cùng UA với `/sn.php`).
- DNS `88.perfectexe.com` (frame 3808/3814) qua 147.32.80.9 trả `60.190.223.75`; SYN đi ngay sau đó (`dns_to_connection.csv`).
- Response: `200`, **`Content-Type: image/jpeg`**, Content-Length 55 808, body đủ 55 808 byte, **bắt đầu `4D 5A 90 00`** (PE). SHA-256 body tính trong bộ nhớ: `76d3d7c35ca21b967c9dcf0125300f56ec74e00e6a3d0a90ff0aa8659b2e3b2b` (`http_pe_responses.csv`).
- Cùng IP 60.190.223.75 phục vụ 3 port: **888** (`/sn.php`, Host `w.nucleardiscover.com`, 8 request, EVD-008), **2012** (`/p/out/kp.exe`, Host `shabi.coolnuff.com`, 2 response PE cùng SHA-256 `739bbb20…`), **88** (`/bd.jpg`).
- `/bd.jpg` và `/kp.exe` cùng kích thước 55 808 byte nhưng **SHA-256 khác nhau**.
- TShark mặc định gán nhãn `KRB5` và không thấy request này (`detection=payload_heuristic`, `wireshark_label=KRB5`).

**Interpretation.** (OBSERVED) File thực thi được giao dưới đuôi `.jpg` và Content-Type ảnh — ngụy trang loại file (gợi ý ATT&CK T1036.008 Masquerade File Type, chờ Lâm duyệt). (INFERRED) 60.190.223.75 là máy chủ đa vai trò của cùng hạ tầng (check-in `/sn.php` + phân phối payload); hai file cùng kích thước khác hash có thể là các bản đóng gói lại của cùng payload — UNCONFIRMED, cần phân tích tĩnh (ngoài phạm vi network forensics, không được tự mở file).

**Lành tính / giới hạn.** Ảnh JPEG hợp lệ không bắt đầu bằng `MZ`. Không chứng minh được file đã được thực thi trên máy nhiễm.

**Mức:** OBSERVED · **Confidence:** Cao · **Trạng thái:** Provisional.

---

## Ảnh Wireshark cần chụp (Thương tự chụp)

Cài đặt chung: View → Time Display Format → **UTC Date and Time of Day** (Ctrl+Alt+7); thêm cột `tcp.stream`; Analyze → Decode As: TCP 6667 → HTTP, TCP 88 → HTTP khi cần. Lưu vào `evidence/thuong/`.

| EVD | File | Display filter | Frame chọn | Trường cần mở rộng |
|---|---|---|---|---|
| EVD-006 | `evidence/thuong/EVD-006_cb2_response_then_syn.png` | `tcp.stream in {88 89} && frame.number <= 2306` | 2297 | HTTP → Line-based text `CB2=212.117.171.138:65500`; cột Time của 2297 và 2303 |
| EVD-007 | `evidence/thuong/EVD-007_socks5_connect_smtp_aol.png` | `(tcp.stream==89 \|\| tcp.stream==141) && tcp.len>0 && !tcp.analysis.retransmission && frame.number<=3242` | 3216 | Data (bytes) `05 01 00 03 0c 73 6d 74 70…02 4b`; **che chuỗi EHLO ở 3241** |
| EVD-008 | `evidence/thuong/EVD-008_sn_php_requests.png` | `http.request.uri contains "/sn.php"` | 4491 | Hypertext Transfer Protocol → Request URI (**che giá trị `c` sau 4 ký tự** khi chia sẻ) |
| EVD-009 | `evidence/thuong/EVD-009_nocomcom_3425exe_host_bytes.png` | `tcp.stream == 13 && http` | 718 | Host header + Packet Bytes offset 0xb0 (`nocomcom.com`) |
| EVD-009 | `evidence/thuong/EVD-009_frame899_mz_contentlength.png` | `frame.number == 899` | 899 | Content-Length 28160; File Data bắt đầu `4d 5a` (không Export Objects) |
| EVD-010 | `evidence/thuong/EVD-010_pe_responses_list.png` | `http.response && http.file_data[0:2] == 4d:5a` | 1918 | cột Info/Content-Length của 16 dòng |
| EVD-011 | `evidence/thuong/EVD-011_finalcortex_gate_post.png` | `ip.addr == 31.192.109.167 && http` | 1959 | HTML Form URL Encoded (**che giá trị `id`**) + response 1962 `120` |
| EVD-012 | `evidence/thuong/EVD-012_sport2275_reuse.png` | `tcp.port == 2275 && ip.addr == 31.192.109.167` | 81158 | Expert Info `TCP Port numbers reused`; cột tcp.stream 3405/4302 |
| EVD-013 | `evidence/thuong/EVD-013_port25_syn_x3.png` | `tcp.stream == 406` | 6502 | ip.id, tcp.seq_raw, Time (3 lần SYN + bản sao) |
| EVD-014 | `evidence/thuong/EVD-014_port4506_syn_x3.png` | `tcp.stream == 986` | 16488 | như EVD-013 |
| EVD-015 | `evidence/thuong/EVD-015_dns_nocomcom_then_syn.png` | `frame.number >= 195 && frame.number <= 214` | 213 | Answers `nocomcom.com A 195.88.191.59`; frame 214 SYN |
| EVD-016 | `evidence/thuong/EVD-016_google_update_204.png` | `frame.number >= 37 && frame.number <= 50` | 48 | HTTP 204 No Content; UA Google Update |
| EVD-017 | `evidence/thuong/EVD-017_smtp_235_587.png` | `smtp.response.code == 235 \|\| smtp.response.code == 535` | 3755 | Response code; **không mở dòng AUTH base64, không chụp địa chỉ email** |
| EVD-018 | `evidence/thuong/EVD-018_mx_direct_ru.png` | `frame.number >= 77436 && frame.number <= 77446` | 77439 | Queries MX + Authority `ns.ripn.net`; IP nguồn 192.93.0.4 |
| EVD-019 | `evidence/thuong/EVD-019_wpad_nxdomain.png` | `frame.number >= 22 && frame.number <= 30` | 24 | Flags rcode = No such name |
| EVD-020 | `evidence/thuong/EVD-020_netbios_camnep_browser.png` | `tcp.stream == 7` | 512 | NBSS Session request; LANMAN NetServerEnum2 |
| EVD-021 | `evidence/thuong/EVD-021_nonstandard_ports.png` | `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport in {65520 2012 888 82 81 88 9541 5296}` | 95 | Statistics → Conversations (TCP) lọc theo filter |
| EVD-022 | `evidence/thuong/EVD-022_irc_label_is_http.png` | `irc` (**không** Decode As) | 2294 | Cột Protocol = IRC nhưng Packet Bytes bắt đầu `POST /?` |
| EVD-023 | `evidence/thuong/EVD-023_capture_duplicates.png` | `tcp.stream == 1299` | 22807 | ip.id `0x2e22` giống 22718, Time delta |
| EVD-024 | `evidence/thuong/EVD-024_http_post_6667_list.png` | `tcp.dstport == 6667 && http.request` (Decode As TCP 6667 → HTTP) | 3341 | danh sách 31 dòng; cột ip.dst; Request URI (**che sau 4 ký tự hex**); header `CB2: 1` |
| EVD-025 | `evidence/thuong/EVD-025_bdjpg_port88_mz.png` | `tcp.stream == 196 && http` (Decode As TCP 88 → HTTP) | 3895 | Content-Type `image/jpeg`; File Data bắt đầu `4d 5a` (**không** Export Objects) |
