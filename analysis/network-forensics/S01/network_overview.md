# Network Overview — S01 (CTU-13 Scenario 1 / Neris)

**Người phụ trách:** Thương — Network Forensics · **Cập nhật:** 2026-11-16 · **Nguồn số liệu:** output của `scripts/forensics_extract.py` (TShark 4.6.9) trong thư mục này; mọi số đã đối chiếu độc lập trong [`data_consistency_check.md`](data_consistency_check.md); lệnh tái lập ở [`REPRODUCE.md`](REPRODUCE.md).

> Quy ước đơn vị: **packet** (gói, có cả bản sao do capture) · **TCP/UDP stream** (`tcp.stream`/`udp.stream` của TShark) · **Zeek conn** · **Argus labeled flow**. Bốn đơn vị này **không** thay thế cho nhau. Thời gian là UTC ISO 8601 + relative time (giây từ packet đầu).

## 1. Metadata capture

| Mục | Giá trị |
|---|---|
| File | `botnet-capture-20110810-neris.pcap` (58 266 506 byte, pcap/Ethernet, snaplen 65 535) |
| SHA-256 | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` (khớp manifest của Thương, Lâm, FND-001(Quý)) |
| SHA-1 | `5b822dc38f8b97f0b966bce4601cf73cb40afbd1` |
| Packet đầu / cuối (UTC) | `2011-08-10T09:01:40.475792Z` / `2011-08-10T13:49:29.289628Z` |
| Thời lượng | 17 268.813836 s (4 h 47 m 48.8 s) |
| Số packet | 323 154 (trong đó ≈ 97 742 là bản sao do capture, xem §8) |
| Data size | 53 096 018 byte; 24.6 kbit/s trung bình |
| Thứ tự thời gian | `Strict time order: False` (capinfos) |
| Phạm vi quan sát | PCAP **chỉ** chứa traffic của VM nhiễm (bắt trên interface của VM — README CTU); traffic normal/background chỉ có trong labeled flows |

**Nhận xét.** File toàn vẹn (hash khớp ở 5 nguồn) và không bị cắt cụt (TShark/capinfos không cảnh báo). Bản `metadata.txt` cũ ghi giờ local (16:01:40) — đã thay bằng UTC. Packet đầu là 09:01:40Z nhưng hoạt động đầu tiên của bot (NBNS đăng ký tên) ở 09:04:23.241037Z, frame 15.

## 2. Các host

| Vai trò | IP | MAC / định danh | Căn cứ (frame) |
|---|---|---|---|
| **Máy nhiễm** | 147.32.84.165 | `08:00:27:b5:b7:19` — OUI `08:00:27` = PCS Systemtechnik (**VirtualBox**); NetBIOS name **SARUMAN** | NBNS Registration `SARUMAN<00>` frame 15 (`2011-08-10T09:04:23.241037Z`, rel 162.765245); khớp README CTU (Windows XP, SARUMAN) |
| Gateway mặc định | 147.32.84.1 | `00:1e:49:db:19:c3` — OUI Cisco | ARP (286 gói) + 238 046 gói từ máy nhiễm có eth.dst này; frame 1 (ARP) |
| DNS resolver nội bộ | 147.32.80.9 | — | DNS query đầu frame 22 (`wpad`); 6 UDP stream, 22 291 packet |
| File/print server nội bộ | 147.32.84.171 | `00:12:3f:79:0a:65`; NetBIOS **CAMNEP-SERVER** | NBSS Session request frame 494, SMB NetServerEnum2 frame 512 |
| Host nội bộ quét FTP vào máy nhiễm | 147.32.96.45 | — | 216 TCP stream tới 147.32.84.165:21 (215 REJ, 1 S0), 09:09:51Z → 13:49:14Z |
| Host nội bộ khác | 147.32.84.79, 147.32.84.85 | `6c:f0:49:ec:bf:09`, `54:52:00:00:00:01` | chỉ ARP/ICMP; 147.32.84.255 là broadcast NBNS |

**Nhận xét.** Định danh máy nhiễm được xác nhận độc lập bằng 3 dấu hiệu: IP theo README, tên NetBIOS SARUMAN, MAC VirtualBox. Ngoài máy nhiễm, chỉ có 5 địa chỉ nội bộ khác xuất hiện; 147.32.96.45 là nguồn duy nhất chủ động kết nối vào máy nhiễm (FTP, đều bị từ chối) — không phải hành vi của bot.

## 3. Protocol distribution (`protocol_hierarchy.txt`, đơn vị packet / byte, có bản sao)

| Giao thức (TShark) | Packet | % packet | Byte | % byte |
|---|---:|---:|---:|---:|
| TCP | 235 622 | 72.91 % | 43 756 694 | 82.41 % |
| UDP | 85 865 | 26.57 % | 9 213 281 | 17.35 % |
| └ DNS | 84 574 | 26.17 % | 9 104 128 | 17.15 % |
| └ TCP `data` (không nhận dạng được giao thức) | 39 356 | 12.18 % | 8 090 404 | 15.24 % |
| └ TLS | 1 873 | 0.58 % | 2 791 845 | 5.26 % |
| └ HTTP | 2 676 | 0.83 % | 2 052 091 | 3.86 % |
| └ SMTP | 1 716 | 0.53 % | 349 176 | 0.66 % |
| └ HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port) — TShark mặc định đếm vào `irc` | 61 | 0.02 % | 20 374 | 0.04 % |
| ARP | 906 | 0.28 % | 54 360 | 0.10 % |
| ICMP | 757 | 0.23 % | 71 443 | 0.13 % |
| NBNS / NBSS+SMB / Browser | 296 / 96 / 111 | 0.09 / 0.03 / 0.03 % | 27 880 / 16 842 / 26 172 | 0.05 / 0.03 / 0.05 % |

**Nhận xét.** DNS chiếm hơn ¼ số packet — bất thường với một máy trạm, do bot tự phân giải MX hàng loạt (§5). 15 % byte là TCP "data" không nhận dạng được: phần lớn là kênh SOCKS5 qua 212.117.171.138:65500 và các kênh nhị phân tới 213.246.53.125:5296 / 184.154.132.106:9541 (§7). 61 packet mang nhãn `irc` là HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port), mức OBSERVED (§6, EVD-024).

## 4. Thống kê kết nối của máy nhiễm (đơn vị: TCP/UDP stream)

- Tổng: **12 859 TCP stream** + **2 758 UDP stream**; máy nhiễm khởi tạo 12 622 TCP / 2 743 UDP.
- Trạng thái 12 622 TCP stream do máy nhiễm khởi tạo: `S0` 10 244 (**81.16 %**), `EST_FIN` 1 080 (8.56 %), `EST_RST` 684 (5.42 %), `REJ` 587 (4.65 %), `PARTIAL` 16, `EST_OPEN` 7, `SYN_ACK_NO_ACK` 4. Tỷ lệ thất bại (S0+REJ) = **85.81 %**.
- Port đích TCP nhiều nhất: 25 (8 489 stream tới 1 469 IP, **100 % S0**), 6667 (1 314 stream tới 478 IP), 80 (1 270), 4506 (902), 65500 (321), 443 (161), 587 (64).

Top 15 đích theo số stream (`top_destinations.csv`; bytes tính theo frame, hai chiều, gồm bản sao):

| # | Đích | Port | Stream | Trạng thái | Packet (dedup) | Byte ra | Byte vào | Lần đầu (UTC) |
|---|---|---|---:|---|---:|---:|---:|---|
| 1 | 209.85.225.27 | 25 | 965 | S0 965 | 5 790 (2 971) | 358 980 | 0 | 2011-08-10T09:17:58.456138Z |
| 2 | 212.117.174.7 | 4506 | 902 | S0 902 | 5 412 (2 772) | 335 544 | 0 | 2011-08-10T09:28:00.380446Z |
| 3 | 174.133.57.141 | 80 | 358 | EST_FIN 311, EST_RST 47 | 5 945 (3 866) | 513 144 | 684 640 | 2011-08-10T09:06:52.959894Z |
| 4 | 209.85.143.27 | 25 | 347 | S0 347 | 2 082 | 129 084 | 0 | 2011-08-10T09:28:43.844401Z |
| 5 | 212.117.171.138 | 65500 | 321 | EST_FIN 197, EST_RST 122, EST_OPEN 2 | 24 569 (20 161) | 11 474 534 | 2 762 450 | 2011-08-10T09:09:23.086554Z |
| 6 | 173.192.170.88 | 80 | 286 | EST_FIN 99, EST_RST 125, S0 61, EST_OPEN 1 | 5 601 | 415 448 | 348 797 | 2011-08-10T09:09:57.858423Z |
| 7 | 205.188.190.1 | 25 | 253 | S0 253 | 1 518 | 94 116 | 0 | 2011-08-10T09:18:16.582127Z |
| 8 | 66.94.237.64 | 25 | 220 | S0 220 | 1 320 | 81 840 | 0 | 2011-08-10T09:16:57.869234Z |
| 9 | 205.188.103.1 | 25 | 216 | S0 216 | 1 296 | 80 352 | 0 | 2011-08-10T09:12:15.652387Z |
| 10 | 64.12.139.193 | 25 | 210 | S0 210 | 1 258 | 77 996 | 0 | 2011-08-10T09:23:43.252182Z |
| 11 | 98.139.175.224 | 25 | 206 | S0 206 | 1 236 | 76 632 | 0 | 2011-08-10T09:22:30.046892Z |
| 12 | 98.139.54.60 | 25 | 176 | S0 176 | 1 056 | 65 472 | 0 | 2011-08-10T09:14:21.603236Z |
| 13 | 64.12.90.65 | 25 | 162 | S0 162 | 972 | 60 264 | 0 | 2011-08-10T09:24:03.808242Z |
| 14 | 74.125.113.27 | 25 | 117 | S0 117 | 692 | 42 904 | 0 | 2011-08-10T09:14:19.642092Z |
| 15 | 64.12.90.1 | 25 | 110 | S0 110 | 660 | 40 920 | 0 | 2011-08-10T09:28:21.636006Z |

Theo **khối lượng** thì khác: 213.246.53.125:5296 (5 stream, 52 584 packet, 3.2 MB) và 184.154.132.106:9541 (3 stream, 46 684 packet, 2.9 MB) đứng đầu `conv,ip`.

**Nhận xét.** Hành vi chủ đạo là **thử kết nối hàng loạt không thành công**: 10 244 stream S0, trong đó toàn bộ 8 489 stream tới port 25 (MX của Google, AOL, Yahoo…) không nhận được gói nào — phù hợp spam trực tiếp tới MX bị chặn ở biên mạng (giả thuyết, chưa xác nhận). Ngược lại, kênh 65500 tới 212.117.171.138 luôn bắt tay thành công và có khối lượng lớn nhất theo byte ra (11.5 MB) — đây là kênh hoạt động thật của bot.

## 5. DNS (đơn vị: query duy nhất sau khử trùng capture)

| Chỉ số | Giá trị |
|---|---|
| Query packet / sau khử trùng | 58 428 / **42 669** (15 759 bản sao capture; 13 469 lần gửi lại thật) |
| Số tên miền khác nhau | **7 212** |
| Loại query | MX 27 108 (63.5 %), A 15 555, PTR 6 |
| Kết quả | NOERROR 21 222 · không phản hồi 16 527 · SERVFAIL 4 457 · **NXDOMAIN 330** · REFUSED 133 |
| Gửi tới resolver nội bộ 147.32.80.9 | 9 273 (21.7 %) |
| **Gửi trực tiếp ra DNS bên ngoài** (`external_direct`) | **33 396 (78.3 %)** tới 2 189 máy chủ khác nhau; 14 675 không phản hồi; 25 853 thuộc `.ru` |
| Query trực tiếp đầu tiên | frame 13754, `2011-08-10T09:26:55.398251Z`, `MX hotmail.com` → 192.33.4.12 (root server) |
| Domain nổi bật (qua resolver nội bộ) | `finalcortex.com` (15 query), `nocomcom.com`, `w.nucleardiscover.com`, `mewgost.com`, `shabi.coolnuff.com`, `88.perfectexe.com`, `ii.ebatmoyhuy.com`, `hn.yigeyuming.com` |
| NXDOMAIN lặp nhiều nhất | `aspmx2..5.l.google.com`, `mernari.ru`, `3960.ovz14.hc.ru` (3 lần), `wpad` (2) |

**Nhận xét.** Từ 09:26:55Z bot bỏ qua resolver nội bộ và tự phân giải lặp (root → TLD → authoritative) cho hàng nghìn MX, chủ yếu `.ru` — dấu hiệu điển hình của spam engine tự tra MX. Domain liên quan C2/tải file lại được phân giải bình thường qua 147.32.80.9 (xem `dns_to_connection.csv`: 117/141 cặp Host–IP có DNS trả đúng IP đích, 21 Host là IP literal, 3 không có DNS trong PCAP). Không thấy dấu hiệu DGA rõ rệt trong tên C2 (entropy thấp, ít NXDOMAIN).

## 6. HTTP / SMTP (không có IRC)

**HTTP** (1 393 request; 1 383 từ máy nhiễm, 10 đi **vào** máy nhiễm qua đường hầm 65500). Cột `detection` trong `http_requests.csv`: **1 361 `dissector`** (TShark mặc định nhận là HTTP) + **32 `payload_heuristic`** (chỉ nhận khi ép `-d tcp.port==6667,http -d tcp.port==88,http`): 31 POST `/?<hex>` tới port 6667 (`wireshark_label`=IRC) và 1 GET `/bd.jpg` tới 60.190.223.75:88 (`wireshark_label`=KRB5).
- 81 Host, 105 IP đích; GET 1 293, POST 84, M-SEARCH 6 (SSDP); status 200 682, 500 319, 302 212, 304 105, 404 15, không phản hồi 41.
- User-Agent lặp: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)` 578, **`ClickAdsByIE 0.9.10`** 360 (toàn bộ tới `1.95622.com`/`a.95622.com` `/p6.asp`, 319 trả 500), `…; waoc)` 179, UA giả Linux Firefox 61, UA rỗng 60, **`Mozilla`** (chuỗi cụt) 31 = các POST CB2 tới port 6667 (EVD-024).
- C2/tải file: `finalcortex.com` 54 (1 GET `/snapbn/ip.php` + 53 POST `/snapbn/gate.php`), `/sn.php` 16 (2 Host), 16 response có body PE `MZ` (`http_pe_responses.csv`), trong đó `GET /bd.jpg?t=…` (Host `88.perfectexe.com:88`, frame 3820) trả `Content-Type: image/jpeg` nhưng body 55 808 byte bắt đầu `4D 5A` (EVD-025).

**SMTP** (đơn vị: TCP stream có lệnh SMTP): 64 phiên, **toàn bộ tới port 587** của 6 máy chủ AOL/Yahoo (64.12.175.136, 64.12.168.40, 205.188.186.137, 205.188.186.167, 98.139.212.139, 98.136.185.95). 63 phiên `AUTH LOGIN`: **53 thành công (235)**, 10 thất bại (535); 53 phiên có `DATA`; 82 `MAIL FROM`, 214 `RCPT TO` (1–12 người nhận/phiên). Phiên đầu frame 3237 (`09:10:49.702923Z`), cuối `13:23:14.658751Z`. Không có phiên SMTP thành công nào trên port 25.

**Không có IRC (OBSERVED).** Lưu lượng port 6667 là **HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)**. Toàn bộ 106 packet có payload trên port 6667: 72 `POST /?<hex> HTTP/1.1` (31 request duy nhất, phần còn lại là bản sao capture/gửi lại), 30 `HTTP/1.1 200` (body `CB2=212.117.171.138:65500`), 4 RST kèm text của middlebox (`Syn Idle expired`, `Go away, we're not home`). Tìm `NICK `, `USER `, `JOIN #`, `PRIVMSG` trong mọi payload TCP: **0** kết quả. Chi tiết kênh: EVD-024.

**Nhận xét.** README CTU mô tả Neris "gửi spam, HTTP C&C, click-fraud" — cả ba đều thấy trực tiếp: SMTP AUTH trên 587, POST định kỳ tới finalcortex.com, và UA `ClickAdsByIE`. Ghi nhận "IRC" trong báo cáo tuần 1 của Thi (61 packet) và `ground_truth_notes.md` của Lâm cần đổi thành "HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port)"; ghi trong handoff.

## 7. Candidate suspicious connections (bàn giao Thi / Quý)

| Candidate | Đích | Đặc trưng (≥ 2) | Khoảng thời gian (UTC) | Finding / EVD |
|---|---|---|---|---|
| C1 — CB2 dispatcher (HTTP-over-6667) | 17 IP ×:6667 (31 stream có POST CB2; 39/1 314 stream port 6667 bắt tay thành công) | HTTP POST trên port 6667 (Wireshark nhận nhầm là IRC theo port); header `CB2: 1`; URI là chuỗi hex dài; UA cụt `Mozilla`; response chứa `CB2=IP:port` | 09:09:22Z → 13:46:46Z | FND-001(Thi/Lâm) · EVD-006, EVD-024 |
| C2 — SOCKS5 ngược | 212.117.171.138:65500 | 321/321 stream bắt tay thành công; byte ra 11.5 MB; byte đầu từ C2 là `0x7e` (313/321 stream), sau đó `05 02 00 02` / `05 00` (SOCKS5); C2 ra lệnh CONNECT tới `smtp.aol.com:587` (68 lần), `login.live.com:443`… | 09:09:23Z → 13:48:38Z | FND-001(Thi/Lâm) (phần chưa xác nhận) · đề xuất NF-01 · EVD-007 |
| C3 — HTTP C2 polling | finalcortex.com 31.192.109.167:80 | 54 stream; POST cố định 62 byte `id=SARU...&version=1337&os=2600&s5=6906&done=`; response luôn `120`; median IAT ≈ 123 s | 09:08:46Z → 11:16:00Z | FND-001(Quý) · EVD-011, EVD-012 |
| C4 — `/sn.php` | 60.190.223.75:888, 94.63.150.20:80 | tham số `c` hex 297–306 ký tự; port 888 phi chuẩn; 16 request trong 2 cụm | 09:06:51Z → 09:13:37Z | FND-002(Thi/Lâm) · EVD-008 |
| C5 — tải PE | 195.88.191.59 (nocomcom.com), 60.190.223.75:2012/88 (`/bd.jpg` ngụy trang JPEG), 61.147.99.179:81, hn.yigeyuming.com:82, ii.ebatmoyhuy.com | 16 response body `4D 5A`; Content-Type octet-stream; URI ngụy trang `.jpg/.gif/.txt/.php` | response 09:06:36Z → 10:10:32Z | FND-003(Thi/Lâm) · EVD-009, EVD-010, EVD-025 |
| C6 — SYN lặp port 4506 | 212.117.174.7:4506 | 902 stream S0, 3 SYN/stream; không có phản hồi; liên tục ~4.3 h | 09:28:00Z → 13:48:03Z | FND-003(Quý) · EVD-014 |
| C7 — kênh nhị phân XOR-like | 213.246.53.125:5296, 184.154.132.106:9541, 78.129.163.119:6251, 78.129.227.128:5231 | port cao phi chuẩn; TShark không nhận dạng (`data`); khối lượng lớn nhất PCAP (1.7–3.2 MB/IP); kênh 5296/9541 mở đầu bằng chuỗi lặp `e0e0e0e0e6` / `e2e2e2e2e4` | stream bắt đầu 09:10:06Z → 09:32:08Z | đề xuất NF-05 · EVD-021 |
| C8 — spam MX/SMTP | port 25 (1 469 IP), port 587 (6 IP), DNS MX trực tiếp | 8 489 stream S0; 53 AUTH thành công; 27 108 query MX | 09:10:49Z → 13:48:44Z | FND-002(Quý) · đề xuất NF-02/NF-03 · EVD-013, 017, 018 |

**Nhận xét.** C1–C3 tạo thành chuỗi điều khiển rõ nhất: dispatcher CB2 chỉ định 212.117.171.138:65500 → bot mở kênh SOCKS5 → C2 dùng bot làm proxy gửi thư qua `smtp.aol.com:587`. Đây là suy luận từ dữ liệu packet (chi tiết ở `packet_evidence.md`), cần Thi tái dựng timeline và Lâm thẩm định.

## 8. Giới hạn quan sát

- **Bản sao do capture:** ≈ 30 % packet là bản sao (97 742 gói < 1 ms + một phần trễ 0.5–1.4 s). Mọi số packet/byte/retransmission chưa khử trùng đều bị thổi phồng; số stream, HTTP, SMTP, DNS (đã khử) không bị ảnh hưởng.
- **Payload mã hóa/không rõ:** TLS 1 873 packet (443/kênh qua SOCKS); kênh 5296/9541/6251/5231 là nhị phân chưa giải mã; tham số `c` của `/sn.php` và URI hex của CB2 chưa giải mã.
- **Giới hạn băng thông 20 kbps** ở đầu ra bot (README CTU) → số lần thử kết nối và khối lượng thấp hơn so với môi trường thật; có thể là nguyên nhân các bản sao trễ (chưa xác nhận).
- **Chỉ có góc nhìn của VM nhiễm:** không thấy traffic normal/background; không chứng minh được việc thực thi file PE hay chiếm quyền tài khoản email (chỉ thấy mã 235).
- **Nhãn TShark theo port** có thể sai: HTTP trên port 6667 (Wireshark nhận nhầm là IRC theo port), HTTP trên port 88 (nhận nhầm là KRB5), `pktc` 857 gói malformed. Bước HTTP ép decode 6667/88; cột `detection`/`wireshark_label` trong `http_requests.csv` ghi rõ 32 request chỉ thấy được nhờ ép decode. Port khác có thể còn HTTP chưa được nhận (chưa quét toàn bộ payload theo heuristic).
- Không có Zeek log trên máy Thương — đối chiếu Zeek dựa trên số của Quý; cần chạy `--zeek-dir`.
