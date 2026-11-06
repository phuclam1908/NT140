# Báo cáo Thẩm định Kỹ thuật Độc lập (Technical Validation Report)

**Đồ án:** NT140 – Malware Network Communication Analysis & Threat Detection  
**Phụ trách:** Lâm – Threat Intelligence & Detection Validation Analyst  
**Đối tượng thẩm định:** Báo cáo và bằng chứng của Thi (Malware Communication Analyst)  
**Phạm vi:** CTU-13 Scenario 1 – Neris Botnet (`botnet-capture-20110810-neris.pcap`)  
**Ngày cập nhật:** 07/11/2026  
**Trạng thái:** Hoàn tất thẩm định Tuần 1  

---

## 1. Tóm tắt Điều hành (Executive Summary)

Trong quy trình làm việc chuẩn của nhóm điều tra mạng, vai trò của Người 4 (Validation Analyst) là thực hiện **thẩm định chéo độc lập (Independent Cross-validation)**, bảo đảm rằng:
1. Mọi nhận định kỹ thuật đều có bằng chứng mạng cụ thể (Frame number, timestamp, stream) hỗ trợ.
2. Không có nhận định nào bị suy diễn chủ quan hoặc "thổi phồng" (Over-claiming).
3. Thiết lập ranh giới rõ ràng giữa **Những gì quan sát được trực tiếp (Observed)**, **Những gì suy luận hợp lý (Inferred)** và **Những gì chưa đủ chứng cứ (Unconfirmed)**.

Tuần 1, thành viên **Ngọc Thi** đã bàn giao hồ sơ gồm:
* Báo cáo phân tích hành vi: [`behavior_evidence.md`](../thi/behavior_evidence.md)
* Bảng dòng thời gian: [`malware_timeline.csv`](../thi/malware_timeline.csv)
* Sơ đồ giao tiếp mạng: [`communication_diagram.png`](../thi/communication_diagram.png)
* Bộ 13 ảnh chụp bằng chứng Wireshark tại [`evidence/thi/`](../../../evidence/thi/)

Sau khi đối chiếu kỹ thuật độc lập với file PCAP gốc và tài liệu CTU-13 của Stratosphere Lab, Lâm xác nhận **bộ hồ sơ của Thi đạt chất lượng kỹ thuật xuất sắc, có tính tái lập cao**. Dưới đây là kết quả thẩm định chi tiết và cập nhật trạng thái chính thức cho từng finding.

---

## 2. Phương pháp Thẩm định Ba chiều (Triangulation Audit Method)

Mỗi finding được thẩm định thông qua 3 nguồn dữ liệu độc lập:

```
                  [1. Network Evidence]
               (Wireshark PCAP, Frame, Hex)
                         /      \
                        /        \
                       /          \
[2. Behavioral Reconstruction] ---- [3. CTU-13 Ground Truth]
  (Thi's Timeline & Report)          (Stratosphere Lab Metadata)
```

1. **Khớp nối kỹ thuật mạng:** Kiểm tra lại Frame ID, TCP Stream index, timestamp tương đối (Relative Time), cờ TCP (SYN, ACK) và payload application-layer.
2. **Khớp nối dòng thời gian:** Kiểm tra thứ tự logic nhân - quả (Causality) giữa các sự kiện trong `malware_timeline.csv`.
3. **Đối chuẩn Ground Truth:** Đối chiếu các địa chỉ IP, cổng dịch vụ với tài liệu công bố chính thức của CTU-13.

---

## 3. Thẩm định Chi tiết Từng Phát hiện (Finding-by-Finding Audit)

### 3.1. Thẩm định FND-001: HTTP response cung cấp endpoint và kết nối TCP tiếp theo
* **Mã bằng chứng:** `EVD-001` (Frame 2297), `EVD-002` (Frame 2303 – 2306)
* **Người phát hiện:** Thi | **Trạng thái ban đầu:** *Đang điều tra / Chưa kiểm chứng độc lập*

#### A. Kết quả xác minh kỹ thuật:
* **Frame 2297 (TCP Stream 88):**
  * Giao tiếp giữa `147.32.84.165:1288` và `200.171.4.222:6667`.
  * Request chứa header `CB2: 1`. Server trả về HTTP `200 OK`, body chứa chuỗi `CB2=212.117.171.138:65500`.
  * *Xác minh:* Đúng chính xác theo ảnh bằng chứng `fnd001_cb2_http_stream.png` và `fnd001_response_frame2297.png`.
* **Frame 2303 – 2306 (TCP Stream 89):**
  * Ngay sau Frame 2297 (tại $t = 462.564911\text{s}$), máy nhiễm gửi TCP SYN tới `212.117.171.138:65500` tại $t = 462.610762\text{s}$.
  * Độ trễ phản ứng: $\Delta t = 462.610762 - 462.564911 = \mathbf{45.85\text{ ms}}$.
  * Máy chủ phản hồi SYN/ACK (Frame 2305) và hoàn thành bắt tay 3 bước với ACK (Frame 2306).
  * *Xác minh:* Độ trễ 45.85 ms là đặc trưng của một tiến trình tự động chạy trên máy (machine-speed execution), không thể là thao tác của con người. Khớp 100% với giả thuyết endpoint redirection của malware.

#### B. Phân loại nhận định:
* **Observed (Quan sát trực tiếp):** Máy nhiễm nhận chuỗi định dạng IP:Port qua HTTP response và lập tức kết nối TCP tới đúng IP:Port đó sau 45.85 ms.
* **Inferred (Suy luận hợp lý):** Đây là cơ chế bàn giao endpoint (Stage-1 Dispatcher bàn giao sang Stage-2 C2 Server).
* **Unconfirmed (Chưa xác nhận):** Chưa giải mã được payload trao đổi sau đó trên cổng 65500 (chưa rõ là kênh IRC tùy biến hay binary shellcode).

#### C. Quyết định thẩm định:
* **Cập nhật trạng thái:** **`VALIDATED`** (Xác thực cơ chế Endpoint Handover; ghi nhận C2 Channel ở mức Provisional).
* **Khuyến nghị:** Bổ sung `200.171.4.222` và `212.117.171.138:65500` vào danh mục IOC mức Confirmed.

---

### 3.2. Thẩm định FND-002: HTTP GET có tham số dài và xuất hiện lặp lại
* **Mã bằng chứng:** `EVD-003` (Frame 4491, Frame 625, TCP Stream 208)
* **Người phát hiện:** Thi | **Trạng thái ban đầu:** *Phân tích sơ bộ / Chưa kiểm chứng độc lập*

#### A. Kết quả xác minh kỹ thuật:
* **Frame 4491 (TCP Stream 208):**
  * Máy nhiễm gửi HTTP `GET /sn.php?c=...` tới `60.190.223.75:888` (`Host: w.nucleardiscover.com:888`).
  * Tham số `c` chứa chuỗi ký tự hex dài bất thường.
  * User-Agent: `Mozilla/4.0 (compatible; MSIE 6.0.2900.2180; Windows NT 5.1.2600)` — chuỗi định danh trình duyệt Internet Explorer 6 trên Windows XP.
  * Server trả về `HTTP/1.1 200 OK`.
* **Frame 625:** Ghi nhận một truy vấn HTTP khác tới cùng máy chủ tại thời điểm trước đó.

#### B. Phân loại nhận định:
* **Observed (Quan sát trực tiếp):** Nhiều HTTP GET gửi tới script `/sn.php` trên cổng phi chuẩn 888 với tham số chuỗi hex dài và User-Agent cố định.
* **Inferred (Suy luận hợp lý):** Hoạt động báo cáo trạng thái / điểm danh tự động của máy nhiễm (HTTP Check-in / Beaconing).
* **Unconfirmed (Chưa xác nhận):**
  * *Chưa thể kết luận là Exfiltration:* Chưa giải mã được nội dung của chuỗi `c`, do đó không thể khẳng định là đánh cắp dữ liệu mật.
  * *Chưa thể kết luận Beaconing có chu kỳ cố định:* Mới chỉ quan sát thấy xuất hiện nhiều lần (multiple occurrences), chưa có phép tính định lượng về khoảng cách thời gian (Inter-arrival time).

#### C. Quyết định thẩm định & Chuyển giao:
* **Cập nhật trạng thái:** **`PROVISIONAL`** (Đã xác thực bất thường cấu trúc HTTP; Tạm hoãn kết luận Beaconing).
* **Bàn giao cho Quý (Traffic Analytics):** Yêu cầu Quý viết script trích xuất toàn bộ timestamp của các request `/sn.php`, tính toán:
  * Mean Inter-Arrival Time ($\mu$).
  * Standard Deviation ($\sigma$).
  * Coefficient of Variation ($\text{CV} = \sigma / \mu$). Nếu $\text{CV} < 0.3$, chính thức xác nhận Periodic Beaconing.

---

### 3.3. Thẩm định FND-003: HTTP response chứa nội dung file thực thi PE Windows
* **Mã bằng chứng:** `EVD-004` (Frame 718, Frame 899, Frame 1744, Frame 2024, TCP Stream 13)
* **Người phát hiện:** Thi | **Trạng thái ban đầu:** *Đang điều tra / Chưa kiểm chứng độc lập*

#### A. Kết quả xác minh kỹ thuật:
* **Frame 718 (TCP Stream 13):** Máy nhiễm gửi request `GET /temp/3425.exe?t=0.3419458 HTTP/1.1` tới `195.88.191.59` (`nomcom.com`).
* **Frame 899:** Server phản hồi HTTP `200 OK`, `Content-Type: application/octet-stream`, `Content-Length: 28160`.
* **Kiểm tra Payload Byte:** Dữ liệu bắt đầu bằng 2 byte `0x4D 0x5A` (ASCII: `MZ`) và chứa chuỗi DOS Stub rõ ràng: `This program cannot be run in DOS mode.`. Đây là cấu trúc không thể chối cãi của một tệp nhị phân PE (Portable Executable) cho hệ điều hành Windows.
* **Các request liên quan:** Frame 1744 (`/bl/client.exe`) và Frame 2024 (`/sv/fjuivgfhurew.exe`) xác nhận máy chủ này là kho lưu trữ nhiều module thực thi khác nhau của mã độc.

#### B. Phân loại nhận định:
* **Observed (Quan sát trực tiếp):** Máy trạm tải tệp thực thi Windows `.exe` dung lượng 28.160 byte từ máy chủ HTTP bên ngoài.
* **Inferred (Suy luận hợp lý):** Mã độc tải thêm payload / module phụ để mở rộng tính năng (Ingress Tool Transfer - MITRE ATT&CK T1105).
* **Unconfirmed (Chưa xác nhận):** Không thể khẳng định file đã được thực thi thành công trên máy (Execution) vì PCAP không lưu telemetry của hệ điều hành.

#### C. Quyết định thẩm định & Khuyến cáo an toàn:
* **Cập nhật trạng thái:** **`VALIDATED`** (Xác thực hành vi tải payload PE qua mạng).
* **Khuyến cáo an toàn nội bộ (Safety Advisory):** Các thành viên tuyệt đối không tái kết xuất (export object) file `.exe` này để chạy thử trên máy thật. Việc phân tích hoàn toàn dựa trên network metadata và mã băm nếu có.

---

## 4. Thẩm định Dòng thời gian (`malware_timeline.csv`)

Lâm đã kiểm tra toàn bộ 8 bản ghi trong [`malware_timeline.csv`](../thi/malware_timeline.csv) do Thi xây dựng:

| Dòng | Relative Time (s) | Frame | Giao tiếp | Đánh giá tính toàn vẹn |
|:---:|---:|:---:|---|---|
| 1 | 315.334906 | 718 | GET `/temp/3425.exe` | Khớp chính xác với Stream 13 |
| 2 | 321.231038 | 899 | Response PE file 200 OK | Khớp thời điểm hoàn thành tải payload |
| 3 | 462.564911 | 2297 | Response chứa `CB2=...` | Khớp sự kiện chỉ định IP |
| 4 | 462.610762 | 2303 | TCP SYN tới port 65500 | Khớp độ trễ 45.85 ms |
| 5 | 462.633239 | 2305 | TCP SYN/ACK từ port 65500 | Phản hồi mạng thực tế |
| 6 | 462.633544 | 2306 | TCP ACK hoàn tất handshake | Bắt tay 3 bước hoàn chỉnh |
| 7 | 716.314495 | 4491 | GET `/sn.php` param hex | Khớp Stream 208 |
| 8 | 716.643539 | 4495 | Response 200 OK | Phản hồi máy chủ C2 |

**Nhận xét:** Dòng thời gian tuân thủ nghiêm ngặt định dạng ISO 8601 UTC, thời gian tương đối đồng bộ với timestamp gốc của capture, không có sự kiện nào bị nghịch đảo thời gian (No causality violation).

---

## 5. Bảng Tổng hợp Trạng thái Thẩm định (Validation Dashboard)

| Mã Finding | Hành vi điều tra | Bằng chứng | Đánh giá của Thi | Trạng thái sau Thẩm định của Lâm | Hành động tiếp theo |
|---|---|---|---|---|---|
| **FND-001** | Chỉ định endpoint và mở TCP socket | EVD-001, EVD-002 | Đang điều tra | **VALIDATED** (Confirmed Handover) | Khóa IOC-001, IOC-002; theo dõi phiên TCP stream 89 |
| **FND-002** | HTTP GET tham số dài `/sn.php` | EVD-003 | Phân tích sơ bộ | **PROVISIONAL** (Structural Anomaly) | Chuyển Quý phân tích độ biến thiên chu kỳ (CV) |
| **FND-003** | Tải file thực thi Windows PE | EVD-004 | Đang điều tra | **VALIDATED** (Confirmed PE Ingress) | Khóa IOC-008, IOC-010; mapping ATT&CK T1105 |

---

## 6. Kế hoạch Phối hợp Kỹ thuật Tuần 2

1. **Giao việc cho Quý (Traffic Analytics):**
   * Sử dụng Zeek trích xuất `http.log` và `conn.log`.
   * Lập trình module tính toán $\text{CV}$ và vẽ biểu đồ phân bố thời gian cho các request `/sn.php` (FND-002) để chốt trạng thái Validated cho Beaconing.
   * Áp dụng khóa Composite Key đã định nghĩa trong [`ground_truth_notes.md`](ground_truth_notes.md) để nối kết quả với `.binetflow`.
2. **Giao việc cho Thương (Network Forensics):**
   * Hoàn thiện `network_connections.csv` và `dns_findings.csv` để Lâm đối chiếu thêm các truy vấn DNS phân giải domain `nomcom.com` và `w.nucleardiscover.com`.
3. **Phần việc tiếp theo của Lâm:**
   * Chuẩn bị kịch bản kiểm thử (Test Matrix) cho bộ quy tắc phát hiện (Detection Rules) chuẩn bị được xây dựng ở Tuần 2.
   * Đo lường chỉ số Precision, Recall và phân tích False Positive khi detector chạy trên tập nhãn `Normal` của CTU-13.
