# Bàn giao findings — Tuần 1 (Quý / Traffic Analytics)

**Dataset:** CTU-13 Scenario 1 — Neris (`147.32.84.165`)  
**Công cụ:** Docker + Zeek 9.0.1, Python/Pandas  
**Trạng thái chung:** Các kết quả định lượng đã chạy trên Zeek logs; **chưa hoàn thành packet-level validation và flow-label alignment**.

| Finding | Nội dung | Mức bằng chứng hiện tại | Tệp |
|---|---|---|---|
| **FND-001** | 54 HTTP connections đến `31.192.109.167:80` / `finalcortex.com`; gồm 1 GET và 53 POST tới `/snapbn/gate.php`; median POST interval 123.46 s; CV POST 0.5415 | HTTP communication lặp lại **được xác nhận bằng logs**; vai trò C2 **cần kiểm chứng thêm** | `evidence/findings/FND-001.md` |
| **FND-002** | 1,930 TCP connection attempts tới `209.85.225.27:25`; đều `S0`, `history=S`, không quan sát packet phản hồi | **Repeated SYN attempts**; chưa xác nhận SMTP hoặc spam thành công | `evidence/findings/FND-002.md` |
| **FND-003** | 1,804 TCP connection attempts tới `212.117.174.7:4506`; đều `S0`, `history=S`, không quan sát packet phản hồi; mean interval ~8.66 s | **Repeated SYN attempts**; chưa xác nhận C2 | `evidence/findings/FND-003.md` |

## Các dữ liệu bàn giao (lưu trong Ubuntu; không commit PCAP / logs lớn)

- `data/processed/scenario-01-neris/zeek/conn.log`, `http.log`
- `reports/week1/generated/flow_statistics.csv`
- `reports/week1/generated/beaconing_results.csv`
- `reports/week1/generated/http_candidate_evidence.csv`
- `reports/week1/generated/http_post_timeline.csv`
- `reports/week1/generated/http_post_intervals.png` (nếu đã tạo)

> **UID caveat:** UID thay đổi giữa các lần chạy Zeek. Trong cùng run có thể nối `conn.log` ↔ `http.log` bằng `uid`; để dò lại packet, dùng timestamp + IP/cổng + frame từ Wireshark.

## Phân công xác minh

- **Thương:** Wireshark: lọc gói của FND-001/002/003; chụp frame number và TCP stream; cập nhật evidence IDs.
- **Thi:** Điều tra nội dung HTTP POST/response của FND-001, đánh giá khả năng C2; đưa event vào timeline.
- **Lâm:** Kiểm chứng tài liệu CTU-13, labeled flows, phương pháp match flow và trạng thái finding/ATT&CK phù hợp.
- **Quý:** Giữ script và kết quả có thể tái lập; kiểm tra outlier của POST intervals; báo cáo thống kê.

**Lưu ý khi tích hợp:** ID có thể trùng với của đồng đội; thống nhất trước khi merge. Không đổi `Pending validation` thành `Validated` nếu chưa có bằng chứng phù hợp.
