# Network Overview — Scenario S01 (CTU-13 Scenario 1 / Neris)

## 1. Metadata capture
| Mục | Giá trị |
|---|---|
| File | botnet-capture-20110810-neris.pcap |
| SHA-256 | |
| Bắt đầu / kết thúc (UTC) | |
| Thời lượng | |
| Số packet | |
| Encapsulation / snaplen | |
| Phạm vi quan sát | Full-payload PCAP chỉ chứa traffic botnet (theo README); normal/background nằm ở labeled flows |

## 2. Các host
| Vai trò | IP | Căn cứ |
|---|---|---|
| Máy nhiễm (ground truth) | 147.32.84.165 | README CTU-13 Scenario 1 |
| DNS server | | Quan sát port 53 |
| Peer nổi bật | | top_destinations.csv |

## 3. Protocol distribution
(Tóm tắt từ protocol_hierarchy.txt — % packet/byte của TCP, UDP, DNS, HTTP, SMTP, IRC…)

## 4. Thống kê kết nối của máy nhiễm
- Tổng số TCP/UDP connection (theo stream, không phải packet):
- Top 10 destination IP / port:
- Tỷ lệ TCP thất bại (S0/REJ):

## 5. DNS
- Số query, số domain khác nhau, số NXDOMAIN:
- Domain nổi bật:

## 6. HTTP / ứng dụng khác
- Host, URI, User-Agent lặp lại:
- SMTP (spam?) / IRC:

## 7. Candidate suspicious connections (chuyển cho Thi và Quý)
| Candidate | Dst | Lý do (≥2 đặc trưng) | Khoảng thời gian | Finding liên quan |
|---|---|---|---|---|

## 8. Giới hạn quan sát
- Packet loss / capture không đầy đủ:
- Payload thiếu / traffic mã hóa:
- Botnet output bị giới hạn 20 kbps (README) → ảnh hưởng volume:
