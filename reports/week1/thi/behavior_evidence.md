# Scenario 01 – Phân tích bằng chứng giao tiếp mạng của Neris

**Đồ án:** NT140 – Malware Network Communication Analysis & Threat Detection  

**Đảm nhận:** Ngoc Thi – Malware Communication Analyst  

**Bộ dữ liệu:** CTU-13, Scenario 1 – Neris  

**File PCAP:** `botnet-capture-20110810-neris.pcap`  

**Công cụ:** Wireshark  

**Trạng thái:** Đang phân tích

## 1. Thông tin bộ dữ liệu

| Thuộc tính | Giá trị |
|---|---|
| Scenario | CTU-13 Scenario 1 – Neris |
| Dung lượng PCAP | Khoảng 58 MB |
| Tổng số packet | 323.154 |
| Ngày capture | 10/08/2011 |
| Thời gian capture | 04:47:48 |
| Định dạng đóng gói | Ethernet |
| Máy nhiễm botnet | `147.32.84.165` |
| SHA-256 | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` |

IP máy nhiễm `147.32.84.165` được xác định dựa trên metadata của CTU-13 Scenario 1.

Thời gian hiển thị trong Wireshark có thể phụ thuộc vào múi giờ của máy phân tích. Khi xây dựng attack timeline, cần chuẩn hóa timestamp để tránh sai lệch.

### 1.1. Thống kê giao thức

Sử dụng `Statistics → Protocol Hierarchy` trong Wireshark để khảo sát các giao thức xuất hiện trong PCAP.

| Giao thức | Số packet | Tỷ lệ |
|---|---:|---:|
| TCP | 235.622 | 72,9% |
| UDP | 85.865 | 26,6% |
| DNS | 84.574 | 26,2% |
| HTTP | 2.676 | 0,8% |
| IRC (Wireshark phân loại theo port 6667) | 61 | Dưới 0,1% |
| TLS | 1.567 | 0,5% |

TCP chiếm phần lớn lưu lượng mạng, trong khi DNS cũng xuất hiện với tỷ lệ đáng kể.

Wireshark ban đầu phân loại 61 packet là IRC. Tuy nhiên, sau khi đối chiếu payload và kết quả Network Forensics của Thương (EVD-022, EVD-024), các packet này thực chất thuộc giao tiếp HTTP trên cổng TCP 6667, không phải bằng chứng về giao thức IRC.

Cụ thể, đã ghi nhận 31 HTTP POST tới 17 địa chỉ IP trên port 6667, sử dụng header `CB2: 1`. Một số response trả về thông tin endpoint dưới dạng `CB2=IP:Port`.

Vì vậy, nhóm không sử dụng 61 packet được Wireshark gán nhãn IRC làm bằng chứng xác nhận kênh IRC C2. Các kết luận về vai trò C2 của kênh HTTP này vẫn cần được phân biệt với những gì quan sát trực tiếp từ payload.

### 1.2. Ảnh khảo sát tổng quan

![Thông tin file PCAP và mã băm](../../../evidence/thi/overview/capture_properties.png)

**Hình 1. Capture File Properties: thông tin bản PCAP, thời lượng và SHA-256.**

![Thống kê phân bố giao thức](../../../evidence/thi/overview/protocol_hierarchy.png)

**Hình 2. Protocol Hierarchy: phân bố các giao thức được Wireshark nhận diện.**

![Danh sách IPv4 Conversations](../../../evidence/thi/overview/ipv4_conversations.png)

**Hình 3. IPv4 Conversations: tổng quan các cặp IP, chưa đủ cơ sở phân loại độc hại.**

---

## 2. FND-001 – HTTP response cung cấp endpoint và kết nối TCP tiếp theo

**Finding ID:** FND-001  

**Evidence ID:** EVD-001, EVD-002  

**Nhóm hành vi:** Nghi vấn C2 Communication  

**Trạng thái:** Đang điều tra

![HTTP response chứa CB2](../../../evidence/thi/fnd001/fnd001_cb2_http_stream.png)

### 2.1. Quan sát (Observation)

Trong quá trình phân tích TCP stream 88, phát hiện một phiên giao tiếp giữa máy nhiễm `147.32.84.165` và địa chỉ bên ngoài `200.171.4.222`.

HTTP request sử dụng phương thức POST, có header tùy chỉnh:

`CB2: 1`

Máy chủ phản hồi HTTP `200 OK`, trong phần nội dung có chuỗi:

`CB2=212.117.171.138:65500`

Thông tin packet:

| Thuộc tính | Giá trị |
|---|---|
| Frame HTTP response | 2297 |
| TCP stream | 88 |
| IP nguồn | `200.171.4.222` |
| Port nguồn | 6667 |
| IP đích | `147.32.84.165` |
| Port đích | 1288 |
| HTTP status | 200 OK |
| Nội dung response | `CB2=212.117.171.138:65500` |

Sau khi nhận HTTP response, máy nhiễm tiếp tục khởi tạo một kết nối TCP đến chính endpoint được cung cấp.

Sử dụng Wireshark Display Filter:

`ip.addr == 212.117.171.138 && tcp.port == 65500`

Kết quả quan sát:

| Frame | Thời gian tương đối (giây) | Sự kiện |
|---|---:|---|
| 2297 | 462,564911 | Nhận HTTP response chứa endpoint |
| 2303 | 462,610762 | Máy nhiễm gửi TCP SYN đến `212.117.171.138:65500` |
| 2305 | 462,633239 | Server phản hồi SYN, ACK |
| 2306 | 462,633544 | Máy nhiễm gửi ACK, hoàn thành TCP three-way handshake |
| 3204 | 548,015184 | Server gửi dữ liệu TCP về máy nhiễm |

Khoảng cách giữa HTTP response tại frame 2297 và TCP SYN tại frame 2303 là khoảng **45,85 ms**.

Như vậy, PCAP cho thấy máy nhiễm nhận một địa chỉ IP và port từ HTTP response, sau đó thiết lập kết nối TCP đến chính endpoint đó.

### 2.1.1. Ảnh bằng chứng EVD-001 – HTTP response chứa endpoint

![HTTP POST và response chứa CB2](../../../evidence/thi/fnd001/fnd001_cb2_http_stream.png)

**Hình 4. TCP stream 88: HTTP POST với header `CB2: 1` và response chứa `CB2=212.117.171.138:65500`.**

![Chi tiết packet phản hồi frame 2297](../../../evidence/thi/fnd001/fnd001_response_frame2297.png)

**Hình 5. Frame 2297: gói HTTP response từ `200.171.4.222:6667` về `147.32.84.165:1288`.**

### 2.1.2. Ảnh bằng chứng EVD-002 – Kết nối TCP tiếp theo

![Các packet liên lạc đến endpoint mới](../../../evidence/thi/fnd001/fnd001_followup_connection.png)

**Hình 6. Bộ lọc `ip.addr == 212.117.171.138 && tcp.port == 65500`: quan sát SYN, SYN/ACK và ACK.**

![Frame 2303 và chỉ số TCP stream 89](../../../evidence/thi/fnd001/fnd001_tcp_syn_frame2303.png)

**Hình 7. Frame 2303: SYN khởi tạo kết nối, `tcp.stream == 89`. Đây là ảnh chi tiết SYN, chưa phải ảnh Follow TCP Stream 89.**

### 2.2. Nhận định (Interpretation)

Chuỗi sự kiện trên gợi ý một cơ chế cung cấp thông tin endpoint để thiết lập phiên liên lạc tiếp theo.

Điều này phù hợp với giả thuyết về hành vi C2, trong đó một máy chủ có thể cung cấp thông tin của một máy chủ liên lạc khác.

Phân tích bổ sung ở mục 2.5 xác nhận payload SOCKS5 CONNECT và một kết nối SMTP liên quan. Điều này củng cố giả thuyết endpoint có chức năng proxy/relay; vai trò đầy đủ của nó trong hệ thống C2 chưa được chứng minh chỉ bằng PCAP.

### 2.3. Mức độ tin cậy và giới hạn

- **Cao:** HTTP response chứa IP endpoint và máy nhiễm thực sự kết nối đến IP đó.

- **Trung bình:** Hai sự kiện có liên hệ về mặt hành vi do diễn ra liên tiếp và sử dụng đúng endpoint được cung cấp.

- **Chưa xác nhận:** Endpoint mới có thực hiện chức năng C2 hay truyền lệnh điều khiển malware hay không.

### 2.4. Hướng điều tra tiếp theo

- Đã phân tích TCP stream 89, xem chi tiết tại mục 2.5.

- Kiểm tra số lượng và thời lượng kết nối đến `212.117.171.138:65500`.

- Xác định có những kết nối lặp lại đến endpoint này hay không.

- Đối chiếu với ground truth của CTU-13.

- Nhờ Thương kiểm chứng lại packet evidence và Lâm xác minh nhận định.

### 2.5. FND-001 Deep Dive – Phân tích kênh SOCKS5 và SMTP Relay
**Evidence liên quan:** EVD-001, EVD-002 (Thi); EVD-007 (Thương)  

**TCP stream:** 89 và 141  

**Trạng thái:** Đã kiểm chứng packet-level; vai trò C2 được đánh giá ở mức suy luận có căn cứ.

#### 2.5.1. Quan sát (Observation)

Sau khi máy nhiễm `147.32.84.165` nhận HTTP response chứa `CB2=212.117.171.138:65500`, máy tiếp tục thiết lập kết nối TCP tới endpoint này qua stream 89.

Khi kiểm tra frame 3216 trong Wireshark, phát hiện TCP payload dài 19 bytes:

`05 01 00 03 0c 73 6d 74 70 2e 61 6f 6c 2e 63 6f 6d 02 4b`

Payload có cấu trúc phù hợp với SOCKS5 theo RFC 1928:

- Version: `0x05` – SOCKS5.

- Command: `0x01` – CONNECT.

- Address Type: `0x03` – Domain name.

- Destination: `smtp.aol.com`.

- Destination port: `587`.

Tiếp tục kiểm tra TCP stream 141, ghi nhận máy nhiễm thiết lập kết nối từ `147.32.84.165:1337` tới `64.12.175.136:587`.

| Frame | Sự kiện quan sát |
|---|---|
| 3216 | TCP stream 89 chứa yêu cầu SOCKS5 CONNECT tới `smtp.aol.com:587`. |
| 3222 | Máy nhiễm gửi TCP SYN tới `64.12.175.136:587`. |
| 3224 | Máy chủ SMTP phản hồi SYN/ACK. |
| 3225 | Máy nhiễm gửi ACK, hoàn thành TCP handshake. |
| 3237 | Máy chủ SMTP gửi banner `220`. |
| 3242 | Máy nhiễm gửi lệnh `EHLO`. |
| 3277 | Máy chủ SMTP trả `535 authentication failed`. |

Trong cửa sổ Follow TCP Stream 89 cũng quan sát được các chuỗi SMTP được chuyển tiếp, bao gồm `220`, `EHLO` và `250`.

#### 2.5.2. Nhận định (Interpretation)

Chuỗi sự kiện cho thấy endpoint `212.117.171.138:65500` không chỉ nhận kết nối TCP mà còn trao đổi dữ liệu theo cấu trúc SOCKS5.

Yêu cầu CONNECT tới `smtp.aol.com:587` xuất hiện trước khi máy nhiễm mở kết nối SMTP tương ứng. Dữ liệu SMTP xuất hiện trong cả hai luồng, hỗ trợ giả thuyết máy nhiễm đang thực hiện chức năng chuyển tiếp lưu lượng thông qua một kênh proxy.

Trong bối cảnh máy đã được CTU-13 gắn nhãn thuộc botnet Neris, đây là dấu hiệu có giá trị cho việc điều tra cơ chế điều khiển và sử dụng máy nhiễm làm trung gian giao tiếp mạng.

#### 2.5.3. Mức độ tin cậy và giới hạn

- **Cao – Observed:** Payload frame 3216 có cấu trúc SOCKS5 CONNECT tới `smtp.aol.com:587`.

- **Cao – Observed:** Máy nhiễm thiết lập kết nối SMTP tới `64.12.175.136:587`.

- **Trung bình đến cao – Inferred:** Hai kết nối có mối liên hệ chức năng và phù hợp với hành vi SOCKS5 relay/proxy.

- **Chưa xác nhận:** Toàn bộ chức năng điều khiển của endpoint SOCKS5 hoặc việc gửi email thành công.

- **Observed:** Phiên SMTP được kiểm tra có phản hồi `535 authentication failed`.

**Kết luận:** FND-001 được mở rộng từ bằng chứng CB2 endpoint handover thành chuỗi giao tiếp CB2 → SOCKS5 CONNECT → SMTP relay, có packet evidence trực tiếp hỗ trợ. Không xem riêng bằng chứng này là xác nhận mọi hoạt động C2 hoặc spam đều thành công.

---

## 3. FND-002 – HTTP GET có tham số truy vấn dài và xuất hiện lặp lại

**Finding ID:** FND-002  

**Evidence ID:** EVD-003  

**Nhóm hành vi:** HTTP Communication / Nghi vấn giao tiếp tự động  

**Trạng thái:** Phân tích sơ bộ

### 3.1. Quan sát (Observation)

Trong PCAP, máy nhiễm `147.32.84.165` gửi các HTTP GET request đến những máy chủ bên ngoài.

Một phiên tiêu biểu:

| Thuộc tính | Giá trị |
|---|---|
| Request frame | 4491 |
| Response frame | 4495 |
| TCP stream | 208 |
| IP nguồn | `147.32.84.165` |
| Port nguồn | 1391 |
| IP đích | `60.190.223.75` |
| Port đích | 888 |
| HTTP Host | `w.nucleardiscover.com:888` |
| HTTP method | GET |
| URI path | `/sn.php` |
| HTTP status | 200 OK |

HTTP GET chứa tham số `c` có giá trị là một chuỗi ký tự dài, chủ yếu có dạng hexadecimal.

Request cũng chứa User-Agent:

`Mozilla/4.0 (compatible; MSIE 6.0.2900.2180; Windows NT 5.1.2600)`

Khi sử dụng bộ lọc:

`http.request && ip.addr == 147.32.84.165`

quan sát được nhiều HTTP request khác có URI `/sn.php`.

Các request này xuất hiện tại nhiều thời điểm và có thể hướng đến những destination khác nhau.

### 3.1.1. Ảnh bằng chứng EVD-003 – HTTP GET với tham số dài

![HTTP GET tại frame 4491](../../../evidence/thi/fnd002/fnd002_http_get_frame4491.png)

**Hình 8. Frame 4491: request `GET /sn.php` từ máy nhiễm tới `60.190.223.75:888`, có tham số `c` dài.**

![Follow HTTP Stream 208](../../../evidence/thi/fnd002/fnd002_http_stream208.png)

**Hình 9. TCP stream 208: nội dung request và response `HTTP/1.1 200 OK`.**

![Packet HTTP khác tại frame 625](../../../evidence/thi/fnd002/fnd002_http_frame625.png)

**Hình 10. Frame 625: một request HTTP tới cùng IP, dùng làm dữ liệu bổ trợ để khảo sát nhiều request; không tự suy ra periodicity.**

### 3.2. Nhận định (Interpretation)

Việc xuất hiện nhiều HTTP request có cấu trúc tương tự và tham số truy vấn dài gợi ý khả năng đây là hoạt động giao tiếp được tự động hóa.

Tuy nhiên, chưa xác định được nội dung thực tế của tham số `c`, cũng chưa chứng minh được tham số này chứa dữ liệu bị đánh cắp hoặc lệnh điều khiển.

Để kiểm tra giả thuyết beaconing, cần phân nhóm những request có cùng đặc điểm giao tiếp, sau đó phân tích khoảng cách thời gian giữa các lần kết nối.

### 3.3. Mức độ tin cậy và giới hạn

- **Cao:** Đã quan sát HTTP GET chứa tham số truy vấn dài.

- **Trung bình:** Có nhiều HTTP request mang cấu trúc tương tự.

- **Chưa xác nhận:** Hoạt động beaconing định kỳ, C2 hoặc exfiltration.

### 3.4. Hướng điều tra tiếp theo

- Thống kê các request đến cùng destination và URI.

- Trích xuất timestamp của từng request.

- Tính inter-arrival time, mean, standard deviation và coefficient of variation (CV).

- Đối chiếu tính định kỳ với những hoạt động mạng hợp lệ.

- Chuyển danh sách request nghi vấn cho Quý để kiểm chứng bằng thống kê.

---

## 4. FND-003 – HTTP response chứa nội dung tương ứng với file thực thi Windows

**Finding ID:** FND-003  

**Evidence ID:** EVD-004  

**Nhóm hành vi:** Nghi vấn Malware Download  

**Trạng thái:** Completed – Network Evidence Analysis

### 4.1. Quan sát (Observation)

Trong quá trình phân tích các HTTP request từ máy nhiễm, phát hiện request truy cập một tài nguyên có phần mở rộng `.exe`.

| Thuộc tính | Giá trị |
|---|---|
| Request frame | 718 |
| TCP stream | 13 |
| IP nguồn | `147.32.84.165` |
| IP đích | `195.88.191.59` |
| HTTP Host | `nocomcom.com` |
| Request URI | `/temp/3425.exe?t=0.3419458` |
| HTTP method | GET |
| HTTP response | 200 OK |
| Server | nginx |
| Content-Type | `application/octet-stream` |
| Content-Length | 28.160 bytes |

Khi sử dụng chức năng Follow HTTP Stream, quan sát được phần nội dung phản hồi bắt đầu bằng chữ ký:

`MZ`

Ngoài ra, phần dữ liệu còn chứa chuỗi:

`This program cannot be run in DOS mode.`

Đây là những đặc điểm thường xuất hiện trong cấu trúc file Portable Executable (PE) của Windows.

Ngoài request trên, còn quan sát được một số request đến những tài nguyên khác có phần mở rộng `.exe`:

| Frame | Destination | URI |
|---|---|---|
| 1744 | `195.88.191.59` | `/bl/client.exe` |
| 2024 | `195.88.191.59` | `/sv/fjuivgfhurew.exe` |

### 4.1.1. Ảnh bằng chứng EVD-004 – Response chứa dữ liệu kiểu PE

![Danh sách các HTTP GET và tài nguyên EXE](../../../evidence/thi/fnd003/http_requests_overview.png)

**Hình 11. Danh sách HTTP requests của `147.32.84.165`, có các URI đuôi `.exe` tại frame 718, 1744 và 2024.**

![Dữ liệu PE trong HTTP response của stream 13](../../../evidence/thi/fnd003/fnd003_pe_response_stream13.png)

**Hình 12. TCP stream 13: response `200 OK`, `Content-Length: 28160`, dữ liệu có tiền tố `MZ`.**

### 4.1.2. Kiểm chứng bổ sung các HTTP response chứa PE-like content

Sau khi đối chiếu các HTTP transactions trong CTU-13 Scenario 1 bằng Wireshark, đã kiểm chứng thêm hai HTTP response của các request `.exe` còn lại.

| Request frame | Response frame | TCP stream | URI | HTTP status | Content-Length |
|---|---|---|---|---|---|
| 718 | 899 | 13 | `/temp/3425.exe` | 200 OK | 28.160 bytes |
| 1744 | 1918 | 63 | `/bl/client.exe` | 200 OK | 93.696 bytes |
| 2024 | 2241 | 81 | `/sv/fjuivgfhurew.exe` | 200 OK | 93.184 bytes |

Các HTTP request đều liên quan máy nhiễm `147.32.84.165` và máy chủ `195.88.191.59`, với HTTP Host được xác định là `nocomcom.com`.

Đối với response frame 1918 và 2241, Wireshark hiển thị `Content-Type: application/octet-stream`, `File Data` có dung lượng tương ứng với `Content-Length` và hai byte đầu dữ liệu là `4D 5A` (`MZ`).

Những bằng chứng này xác nhận máy nhiễm đã nhận các HTTP response chứa dữ liệu có cấu trúc PE-like. Kết quả không tự chứng minh các file đã được lưu vào ổ đĩa, thực thi thành công hoặc chắc chắn là mã độc.

**Trạng thái FND-003:** Completed – Network Evidence Analysis; việc xác định chức năng và mức độ độc hại của file nằm ngoài phạm vi bằng chứng mạng hiện tại.

![PE response frame 1918](../../../evidence/thi/fnd003/fnd003_pe_response_frame1918.png)

**Hình 13. Frame 1918: HTTP 200 OK, File Data 93.696 bytes, chữ ký MZ.**

![PE response frame 2241](../../../evidence/thi/fnd003/fnd003_pe_response_frame2241.png)

**Hình 14. Frame 2241: HTTP 200 OK, File Data 93.184 bytes, chữ ký MZ.**

### 4.2. Nhận định (Interpretation)

HTTP response của request `/temp/3425.exe` chứa nội dung có đặc điểm phù hợp với file thực thi PE của Windows.

Điều này cho thấy có hoạt động truyền dữ liệu mang nội dung giống file thực thi từ máy chủ bên ngoài đến máy nhiễm.

Đây là dấu hiệu phù hợp với hướng điều tra malware download, nhưng chỉ từ network evidence chưa thể xác nhận file đã được lưu trên ổ đĩa, được thực thi hoặc thực sự là mã độc.

### 4.3. Mức độ tin cậy và giới hạn

- **Cao:** HTTP request đến tài nguyên `.exe` và server trả về HTTP 200 OK.

- **Cao:** Nội dung response có chữ ký `MZ` và chuỗi đặc trưng của PE.

- **Chưa xác nhận:** Toàn bộ dữ liệu có được capture đầy đủ hay không.

- **Chưa xác nhận:** File được thực thi hoặc có hành vi độc hại.

### 4.4. Hướng điều tra tiếp theo

- ~~Kiểm tra tính đầy đủ của HTTP response, đối chiếu với Content-Length.~~ (Hoàn thành – xem 4.1.2)

- ~~Phân tích response metadata của những request `.exe` khác.~~ (Hoàn thành – frames 1918, 2241 đã kiểm chứng)

- Kiểm tra các kết nối mạng xuất hiện sau thời điểm truyền file.

- Đối chiếu với ground truth và bối cảnh của scenario.

- Không thực thi file nghi vấn trong môi trường máy thật.

---

## 5. Tổng hợp bằng chứng

| Finding | Evidence | Hành vi quan sát | Trạng thái |
|---|---|---|---|
| FND-001 | EVD-001, EVD-002; tham chiếu EVD-007 (Thương) | CB2 cung cấp endpoint → SOCKS5 CONNECT → SMTP relay | Đã kiểm chứng packet-level; C2 inferred |
| FND-002 | EVD-003 | HTTP GET có tham số dài và nhiều request tương tự | Phân tích sơ bộ |
| FND-003 | EVD-004 | HTTP response chứa nội dung phù hợp với file PE | Completed – Network Evidence Analysis |

Ba finding phản ánh các quan sát có bằng chứng packet-level ở những mức độ khác nhau. FND-001 đã được bổ sung phân tích SOCKS5/SMTP; chưa thể từ đó suy ra toàn bộ chức năng C2 hoặc việc gửi email thành công. FND-002 và FND-003 vẫn cần các bước xác minh còn lại.

## 6. Kết luận

Qua phân tích PCAP của CTU-13 Scenario 1 – Neris bằng Wireshark, đã ghi nhận được ba nhóm dấu hiệu đáng chú ý:

- **Giao tiếp liên quan đến endpoint:** Máy nhiễm nhận HTTP response chứa endpoint, kết nối tới đó và trao đổi SOCKS5 CONNECT liên quan phiên SMTP (xem FND-001).

- **Giao tiếp HTTP có cấu trúc lặp:** Xuất hiện các HTTP GET request có tham số dài và cấu trúc tương tự, cần kiểm chứng thêm tính định kỳ.

- **Truyền dữ liệu dạng file thực thi:** Phát hiện HTTP response chứa nội dung có đặc điểm phù hợp với file PE của Windows.

Những bằng chứng này tạo cơ sở để tiếp tục tái dựng hành vi malware, kiểm tra giả thuyết C2 communication và malware download. Tuy nhiên, các kết luận về vai trò C2, beaconing và tính độc hại của file vẫn cần được đối chiếu với ground truth và các bằng chứng bổ sung.

