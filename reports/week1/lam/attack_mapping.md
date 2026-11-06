# MITRE ATT&CK Mapping & Threat Intelligence Context

**Đồ án:** NT140 – Malware Network Communication Analysis & Threat Detection  
**Phụ trách:** Lâm – Threat Intelligence & Detection Validation Analyst  
**Scenario:** CTU-13 Scenario 1 – Neris Botnet (`CTU-Malware-Capture-Botnet-42`)  
**Host kiểm tra:** `147.32.84.165`  
**Ngày cập nhật:** 07/11/2026  
**Trạng thái:** Hoàn thành (Quy chuẩn Tuần 1)  

---

## 1. Phương pháp luận Ánh xạ MITRE ATT&CK (Mapping Methodology)

Trong điều tra mạng, sai lầm lớn nhất là **"Over-mapping"** — chỉ cần thấy xuất hiện giao thức HTTP thì lập tức gán nhãn T1071, hoặc thấy lưu lượng ra ngoài thì vội vàng kết luận Exfiltration.

Theo quy chuẩn của đồ án:
1. **Phải có bằng chứng mạng trực tiếp (Direct Network Evidence):** Kỹ thuật chỉ được ánh xạ khi có gói tin, luồng kết nối hoặc chữ ký cụ thể chứng minh hành vi đó phục vụ mục đích tấn công.
2. **Phân định rõ ràng giữa "Quan sát" và "Suy luận":**
   * *Quan sát:* Thấy gói tin HTTP GET tải file `.exe`.
   * *Ánh xạ ATT&CK:* Ingress Tool Transfer (T1105).
   * *Không được suy luận vượt giới hạn:* Không tự kết luận file `.exe` đã được thực thi thành công nếu không có bằng chứng từ endpoint.
3. **Minh bạch các kỹ thuật bị loại trừ (Excluded Techniques):** Ghi rõ những kỹ thuật nghi vấn nhưng chưa đủ bằng chứng để tránh thiên kiến điều tra.

---

## 2. Bảng tổng hợp Kỹ thuật ATT&CK đã xác thực

| Tactic | Technique ID | Technique Name | Sub-technique | Finding liên quan | Mức độ tin cậy |
|---|---|---|---|---|---|
| **Command and Control** (TA0011) | **T1071** | Application Layer Protocol | **T1071.001** (Web Protocols) | FND-001, FND-002 | **Cao (Confirmed)** |
| **Command and Control** (TA0011) | **T1571** | Non-Standard Port | — | FND-001, FND-002 | **Cao (Confirmed)** |
| **Command and Control** (TA0011) | **T1095** | Non-Application Layer Protocol | — (Raw TCP Channel) | FND-001 | **Trung bình (Inferred)** |
| **Command and Control** (TA0011) / **Lateral Movement** (TA0008) | **T1105** | Ingress Tool Transfer | — | FND-003 | **Cao (Confirmed)** |

---

## 3. Phân tích Chi tiết Từng Kỹ thuật

### 3.1. T1071.001 – Application Layer Protocol: Web Protocols
* **Mô tả kỹ thuật:** Kẻ tấn công sử dụng các giao thức web ở tầng ứng dụng (HTTP/HTTPS) để che giấu lưu lượng điều khiển C2 lẫn vào lưu lượng duyệt web thông thường của mạng doanh nghiệp.
* **Bằng chứng mạng thực tế:**
  * **Tại `FND-001` (Frame 2297, TCP Stream 88):** Máy nhiễm `147.32.84.165` gửi HTTP POST với header tùy biến độc quyền `CB2: 1` tới `200.171.4.222:6667`. Server trả về mã `HTTP/1.1 200 OK` chứa nội dung định tuyến endpoint `CB2=212.117.171.138:65500`. Đây là việc sử dụng HTTP thuần túy làm vỏ bọc truyền lệnh điều phối C2 (Stage-1 Dispatcher).
  * **Tại `FND-002` (Frame 4491, TCP Stream 208):** Máy nhiễm gửi các truy vấn `GET /sn.php?c=...` tới `60.190.223.75:888`. Toàn bộ tham số truy vấn là chuỗi hex dài, cho thấy việc dùng HTTP GET để gửi thông tin định danh máy trạm lên C2 server.
* **Lập luận xác thực:** Cả hai phiên HTTP này không phục vụ mục đích người dùng duyệt web (User-Agent cổ điển IE6, định dạng tham số tự động, port phi chuẩn). Đây là bằng chứng vững chắc cho T1071.001.

---

### 3.2. T1105 – Ingress Tool Transfer
* **Mô tả kỹ thuật:** Kẻ tấn công chuyển các công cụ tấn công, tệp nhị phân hoặc payload bổ sung từ hệ thống bên ngoài vào mạng nội bộ nạn nhân.
* **Bằng chứng mạng thực tế:**
  * **Tại `FND-003` (Frame 718 – 899, TCP Stream 13):** Máy nhiễm tạo kết nối HTTP GET yêu cầu tài nguyên `http://nomcom.com/temp/3425.exe?t=0.3419458` trên máy chủ `195.88.191.59`.
  * **Phân tích Payload:** Server phản hồi `200 OK`, `Content-Type: application/octet-stream`, `Content-Length: 28160`. Dữ liệu trả về bắt đầu bằng 2 byte ma thuật `0x4D 0x5A` (`MZ`) và chứa chuỗi DOS Stub rõ ràng: `This program cannot be run in DOS mode.`. Đây là cấu trúc tiêu chuẩn của một tệp thực thi Windows Portable Executable (PE).
  * **Các truy vấn tiếp theo:** Frame 1744 (`/bl/client.exe`) và Frame 2024 (`/sv/fjuivgfhurew.exe`) từ cùng IP cho thấy hoạt động kéo thêm nhiều module mã độc vào máy trạm.
* **Lập luận xác thực:** Lưu lượng mạng thể hiện rõ việc truyền tệp nhị phân hoàn chỉnh từ bên ngoài vào. Đáp ứng chính xác định nghĩa của T1105.
* *Giới hạn ghi nhận:* Từ network PCAP chỉ xác nhận việc tệp đã được truyền qua mạng thành công; chưa thể xác nhận file có được ghi xuống ổ đĩa và thực thi (Execution) hay không nếu không có telemetry từ endpoint.

---

### 3.3. T1571 – Non-Standard Port
* **Mô tả kỹ thuật:** Kẻ tấn công thiết lập kết nối C2 hoặc dịch vụ mạng trên các cổng không thuộc quy chuẩn IANA nhằm vượt qua các quy tắc tường lửa đơn giản (Egress Filtering bypass).
* **Bằng chứng mạng thực tế:**
  * **`212.117.171.138:65500` (FND-001):** Sử dụng cổng TCP `65500` — sát giới hạn tối đa của cổng TCP (65535), hoàn toàn không phải cổng dịch vụ chuẩn nào của hệ điều hành.
  * **`60.190.223.75:888` (FND-002):** Chạy giao thức HTTP trên cổng TCP `888` thay vì cổng 80 chuẩn.
  * **`200.171.4.222:6667` (FND-001):** Cổng 6667 vốn dành cho IRC, nhưng lại truyền tải giao thức HTTP kèm header `CB2: 1`.
* **Lập luận xác thực:** Sự hiện diện của lưu lượng C2 trên các cổng phi chuẩn là đặc trưng hành vi rõ rệt giúp xây dựng quy tắc phát hiện ở Tuần 2.

---

### 3.4. T1095 – Non-Application Layer Protocol
* **Mô tả kỹ thuật:** Giao tiếp điều khiển được truyền tải trực tiếp trên tầng giao vận (Transport Layer) như raw TCP/UDP mà không sử dụng các giao thức tầng ứng dụng phổ biến.
* **Bằng chứng mạng thực tế:**
  * Tại **Frame 2303 – 2306 (TCP Stream 89)**, ngay sau khi nhận địa chỉ `212.117.171.138:65500` từ phản hồi HTTP, máy nhiễm bắt tay 3 bước TCP và truyền dữ liệu dạng thô (raw byte stream) mà Wireshark không phân giải được theo bất kỳ giao thức tầng ứng dụng chuẩn nào.
* **Lập luận xác thực:** Phù hợp với giả thuyết C2 sử dụng socket TCP nhị phân tùy biến riêng của biến thể botnet Neris.

---

## 4. Các Kỹ thuật Bị Loại trừ / Chưa đủ Căn cứ (Excluded / Unconfirmed Techniques)

Để giữ vững tính trung thực học thuật và chuẩn mực điều tra, các kỹ thuật sau **tuyệt đối không được đưa vào danh sách xác thực** ở giai đoạn hiện tại:

### 4.1. T1041 – Exfiltration Over C2 Channel (Đánh cắp dữ liệu qua kênh C2)
* *Lý do loại trừ:* Mặc dù tại `FND-002` tham số `c` trong `/sn.php` chứa chuỗi hex rất dài, nhưng hiện tại:
  1. Chưa giải mã được chuỗi hex này là gì (có thể là mã hash định danh máy, cấu hình phần cứng, hoặc chỉ là heartbeat beacon).
  2. Không có bằng chứng về việc tài liệu, file mật khẩu hay dữ liệu nhạy cảm bị đánh cắp khỏi máy trạm.
* *Kết luận:* Ghi nhận là giả thuyết khả nghi, **chưa đủ căn cứ xác nhận T1041**.

### 4.2. T1059 – Command and Scripting Interpreter (Thực thi lệnh shell/script)
* *Lý do loại trừ:* Đây là kỹ thuật thuộc Tactic Execution. Với phạm vi chỉ phân tích Network PCAP mà không có Windows Event Logs (Event ID 4688) hay Sysmon, không thể chứng minh mã độc đã gọi `cmd.exe` hay `powershell.exe`.
* *Kết luận:* Nằm ngoài khả năng quan sát của tập dữ liệu mạng hiện tại.

---

## 5. Bối cảnh Mối đe dọa (Threat Intelligence Context): Neris Botnet

* **Họ mã độc:** Neris (còn được biết đến dưới các tên nhận diện của AV như *Win32/Neris*, *Trojan.Neris*).
* **Kiến trúc C2:** Neris là họ botnet đa kênh (Multi-tier C2 Architecture):
  1. Sử dụng HTTP/Web-based C2 để thực hiện bước điểm danh (Beacon/Check-in), báo cáo trạng thái và nhận chỉ định server kết nối tiếp theo (Dispatcher/Redirector).
  2. Sử dụng IRC hoặc Raw TCP Socket trên các port ngẫu nhiên dải cao để duy trì kênh ra lệnh thời gian thực từ kẻ điều khiển.
  3. Tích hợp module gửi thư rác số lượng lớn (Spam Engine qua SMTP port 25) và module quét tìm lỗ hổng mạng để lây lan tự động.
* **Mối liên hệ với dữ liệu quan sát:** Toàn bộ chuỗi phát hiện của Thi (`FND-001`, `FND-002`, `FND-003`) khớp hoàn toàn với mô hình hoạt động kinh điển của họ Neris được ghi nhận trong các báo cáo Threat Intelligence quốc tế.

---

## 6. Đề xuất Yêu cầu Kỹ thuật cho Detection Engineer (Quý – Tuần 2)

Dựa trên kết quả mapping ATT&CK, Lâm khuyến nghị Quý phát triển các bộ quy tắc phát hiện:
1. **Rule T1571 (Non-standard Web Port):** Phát hiện các phiên HTTP bắt đầu trên port khác 80/443/8080 (ví dụ: port 888, 6667).
2. **Rule T1071.001 (Beaconing Anomaly):** Đo lường chu kỳ kết nối lặp lại tới các endpoint web có URI ngắn và tham số mã hóa hex dài (`/sn.php`).
3. **Rule T1105 (Executable Ingress Transfer):** Cảnh báo khi có HTTP Response chứa Content-Type `octet-stream` kèm chữ ký `0x4D 0x5A` từ máy chủ bên ngoài không thuộc danh sách tin cậy.
