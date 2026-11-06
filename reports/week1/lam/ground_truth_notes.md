# CTU-13 Ground Truth & Dataset Integrity Specification

**Đồ án:** NT140 – Malware Network Communication Analysis & Threat Detection  
**Phụ trách:** Lâm – Threat Intelligence & Detection Validation Analyst  
**Bộ dữ liệu:** CTU-13 Dataset (Stratosphere Laboratory, Czech Technical University)  
**Ngày cập nhật:** 07/11/2026  
**Trạng thái:** Hoàn thành (Quy chuẩn Tuần 1)  

---

## 1. Giới thiệu và Lựa chọn Bộ dữ liệu

Bộ dữ liệu **CTU-13** là tập dữ liệu lưu lượng mạng thực tế về botnet được thu thập tại Đại học Kỹ thuật Séc (CTU) vào năm 2011 bởi nhóm nghiên cứu Stratosphere Laboratory (*Sebastian Garcia et al., 2014*). CTU-13 bao gồm 13 kịch bản (scenario) độc lập, mô phỏng các biến thể mã độc khác nhau hoạt động trong môi trường mạng kết hợp giữa máy nhiễm botnet và mạng nội bộ của trường đại học.

Nhóm nghiên cứu thống nhất lựa chọn 3 scenario đại diện:

| Scenario | Tên Capture | Malware | Vai trò | Mục tiêu nghiên cứu chính |
|---|---|---|---|---|
| **Scenario 1** | `CTU-Malware-Capture-Botnet-42` | Neris | **Primary (Trọng tâm)** | Giao tiếp C2, IRC, cơ chế chỉ định endpoint (endpoint handover), HTTP lặp lại, tải payload PE |
| **Scenario 5** | `CTU-Malware-Capture-Botnet-46` | Virut | Secondary 1 | Giao tiếp HTTP C2, quét cổng (port scanning), traffic liên quan đến web |
| **Scenario 13** | `CTU-Malware-Capture-Botnet-54` | Virut | Secondary 2 | Phân tích lưu lượng ra ngoài (outbound traffic), so sánh biến thể C2 với Scenario 5 |

> **Nguyên tắc trọng tâm tuần 1:** Dồn 100% nguồn lực điều tra chuyên sâu và kiểm chứng độc lập trên **Scenario 1 (Neris)**. Scenario 5 và 13 dùng làm đối chuẩn mở rộng cho mô hình detection ở tuần 2 và tuần 3.

---

## 2. Bản chất các dạng dữ liệu trong CTU-13 & Giới hạn quan sát

Một trong những sai lầm phổ biến nhất trong phân tích mạng là nhầm lẫn giữa phạm vi quan sát của file PCAP và file Flow. Đối với CTU-13, Stratosphere Lab cung cấp các định dạng với phạm vi dữ liệu hoàn toàn khác biệt:

```
CTU-13 Scenario Data Architecture
│
├── Full-Payload PCAP (Công khai)
│   └── CHỈ CHỨA lưu lượng của máy botnet (Infected Host: 147.32.84.165)
│       └── Phục vụ: Network Forensics thủ công (Thương) & Tái dựng hành vi (Thi)
│
├── Bidirectional Flows có nhãn (.binetflow / .biargus)
│   └── CHỨA ĐẦY ĐỦ: Botnet flows + Normal flows + Background flows
│       └── Phục vụ: Traffic Analytics (Quý) & Detection Validation / Benchmark (Lâm)
│
└── Truncated PCAP / Web Flows
    └── Lưu lượng header tóm tắt của mạng khuôn viên trường
```

### Giới hạn quan sát cốt lõi:
1. **Không thể tìm thấy Benign Traffic trong Full PCAP:** File PCAP công khai tải về (`botnet-capture-20110810-neris.pcap`) chỉ ghi lại gói tin liên quan đến máy nhiễm `147.32.84.165`. Các kết nối của người dùng bình thường trong trường đại học không có trong bản full PCAP này vì lý do bảo mật quyền riêng tư (privacy preservation).
2. **Hệ quả đối với phân tích:**
   * Không thể so sánh lưu lượng benign và malicious trực tiếp trong file PCAP.
   * Để kiểm tra độ chính xác phát hiện (Precision/Recall) hoặc đo False Positive, bắt buộc phải sử dụng tệp luồng hai chiều **`.binetflow`**.

---

## 3. Hệ thống Nhãn Ground Truth (Ground Truth Label Taxonomy)

Dữ liệu flow của CTU-13 được gán nhãn tự động và bán tự động bởi nhóm tác giả CTU theo 4 nhóm nhãn chính:

```
[Flow Label Taxonomy]
├── Botnet      : Lưu lượng tấn công phát sinh từ botnet (Spam, Scan, DDoS, Clickfraud)
├── C&C         : Lưu lượng điều khiển trực tiếp giữa bot và Command & Control server
├── Normal      : Lưu lượng sạch được chứng thực từ người dùng hợp lệ
└── Background  : Lưu lượng khuôn viên trường chưa được gán nhãn cụ thể (Unverified)
```

### Quy tắc kiểm chứng nhãn nghiêm ngặt (Validation Rules):

> [!IMPORTANT]
> **QUY TẮC SỐ 1: TUYỆT ĐỐI KHÔNG TỰ COI `Background` LÀ `Normal` (Benign)**
> * Nhãn `Normal` là lưu lượng từ các máy trạm hợp lệ đã được kiểm tra và xác nhận là sạch. Đây là tập mẫu **Benign duy nhất** được phép dùng làm ground truth âm tính (Negative Ground Truth).
> * Nhãn `Background` bao gồm hàng triệu luồng mạng của toàn trường đại học tại thời điểm capture. Nhóm tác giả CTU-13 **không đảm bảo** rằng trong mạng trường đại học lúc đó không có máy tính nào khác bị nhiễm mã độc hay có hành vi bất thường. Do đó, việc tự ý gán `Background = Normal` sẽ làm sai lệch hoàn toàn kết quả đánh giá mô hình phát hiện (gây rủi ro Data Contamination).

### Bảng ánh xạ nhãn chuẩn hóa cho mô hình phát hiện:

| Nhãn gốc trong `.binetflow` | Phân loại chuẩn hóa | Sử dụng trong đánh giá | Ý nghĩa thực nghiệm |
|---|---|---|---|
| `flow=From-Botnet-V42-TCP-CC...` | **Malicious (C&C)** | True Positive Candidate | Lưu lượng điều khiển C2 đã xác nhận |
| `flow=From-Botnet-V42-TCP-Attempt...` | **Malicious (Botnet)** | True Positive Candidate | Hành vi quét mạng hoặc kết nối botnet |
| `flow=From-Normal-V42-Jist...` | **Benign (Normal)** | True Negative Candidate | Lưu lượng người dùng thật đã được thẩm định |
| `flow=Background...` | **Unlabeled / Excluded** | Exclude from Metric Calc | Dữ liệu nền, không dùng để tính Precision/Recall chuẩn |

---

## 4. Phương pháp luận đối chiếu Flow và Zeek Logs (Flow Alignment Methodology)

Trong Tuần 2, Quý (Analytics) sẽ dùng Zeek để trích xuất `conn.log` từ PCAP và xây dựng thuật toán phát hiện, sau đó Lâm (Validation) sẽ đối chiếu với nhãn CTU-13.

### 4.1. Cảnh báo lỗi kỹ thuật ghép dòng (Row-order Matching)
* **Tuyệt đối không được ghép `conn.log` với `.binetflow` theo thứ tự dòng.**
* Lý do: Zeek và phần mềm tạo Argus flow (`ra`) có cơ chế time-out, cách gộp flow, và thời điểm ghi log khác nhau. Hai file này hoàn toàn lệch số dòng và thứ tự ghi nhận.

### 4.2. Khóa liên kết chuẩn hóa (Flow-Matching Composite Key)
Để liên kết một kết nối từ Zeek sang nhãn Ground Truth của CTU-13, thuật toán bắt buộc phải dùng **Composite Key** gồm 5-tuple kết hợp dung sai thời gian:

$$\text{Key} = \left( \text{SrcIP}, \text{DstIP}, \text{SrcPort}, \text{DstPort}, \text{Protocol} \right)$$

Kèm điều kiện thời gian:
$$|T_{\text{Zeek\_start}} - T_{\text{Argus\_start}}| \le \Delta t \quad (\text{với } \Delta t \approx 1.0\text{s} - 2.0\text{s})$$

### 4.3. Các mức độ đánh giá (Evaluation Granularity)
Nhóm thống nhất xác định 4 mức độ đánh giá:
1. **Flow-level (Cấp độ luồng):** Đánh giá xem từng flow riêng lẻ có bị gán nhãn sai hay không. Mức này nhạy cảm nhất với độ lệch time-out giữa các tool.
2. **Endpoint-level (Cấp độ máy chủ):** Đánh giá khả năng xác định đúng máy nạn nhân (`147.32.84.165`) và các IP máy chủ C2.
3. **Destination-level (Cấp độ đích đến):** Đánh giá tỷ lệ phát hiện chính xác các IP/Domain độc hại (IOC) so với danh sách external IP sạch.
4. **Time-window-level (Cấp độ khung thời gian):** Đánh giá xem trong cửa sổ thời gian $W$ (ví dụ: 60s, 300s), hệ thống có kích hoạt cảnh báo khi malware hoạt động hay không.

---

## 5. Định nghĩa Chỉ số Đánh giá (Evaluation Metrics Formulation)

Để chuẩn bị cho giai đoạn kiểm thử bộ phát hiện ở Tuần 2, Lâm thiết lập hệ thống công thức đánh giá chuẩn hóa:

| Ký hiệu | Tên gọi | Định nghĩa trong ngữ cảnh đồ án |
|---|---|---|
| **TP** | True Positive | Flow/Sự kiện độc hại (`Botnet`/`C&C`) được detector phát hiện chính xác |
| **FP** | False Positive | Flow/Sự kiện hợp lệ (`Normal`) bị detector báo nhầm là độc hại |
| **TN** | True Negative | Flow/Sự kiện hợp lệ (`Normal`) được detector nhận định chính xác là bình thường |
| **FN** | False Negative | Flow/Sự kiện độc hại (`Botnet`/`C&C`) bị detector bỏ lọt |

### Các chỉ số bắt buộc báo cáo:

1. **Precision (Độ chính xác):**
   $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
   *Ý nghĩa:* Trong số các cảnh báo được hệ thống đưa ra, có bao nhiêu phần trăm là mối đe dọa thực sự? Tránh báo động giả khiến SOC mệt mỏi (Alert Fatigue).

2. **Recall / True Positive Rate (Độ nhạy):**
   $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
   *Ý nghĩa:* Trong toàn bộ lưu lượng độc hại thực tế, hệ thống bắt được bao nhiêu phần trăm? Tránh để lọt mã độc lẩn khuất.

3. **F1-Score (Trung bình điều hòa):**
   $$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

4. **False Alarm Rate (FAR / FPR):**
   $$\text{FAR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

---

## 6. Hồ sơ Ground Truth cho Scenario 1 (Neris)

Dựa trên tài liệu chính thức của Stratosphere Lab cho capture `CTU-Malware-Capture-Botnet-42`:

* **Thời gian bắt đầu:** 2011/08/10 11:10:48 CEST (khoảng 09:10:48 UTC)
* **Thời lượng:** 04:47:48
* **Endpoint bị nhiễm (Botnet):** `147.32.84.165` (Hệ điều hành: Windows XP SP2/SP3 mô phỏng)
* **Giao thức điều khiển C2 đã ghi nhận trong hồ sơ gốc:**
  * IRC Protocol: Kết nối đến IRC server trung tâm để nhận lệnh (channel command).
  * HTTP GET/POST: Giao tiếp web định kỳ, nhận lệnh chuyển hướng và tải payload phụ.
* **Hành vi botnet:** Thực hiện gửi thư rác (SPAM mail qua SMTP port 25), quét cổng NetBIOS/SMB (TCP 139, 445), và thực hiện các kết nối định kỳ.

---

## 7. Nguyên tắc Chống Thiên kiến và Đảm bảo Tính Tái lập

1. **Không điều chỉnh ngưỡng (Threshold Tuning) trên tập kiểm thử:** Không được dùng chính dữ liệu quan sát của Scenario 1 để "hard-code" các ngưỡng phát hiện (ví dụ: hard-code port `65500` hoặc đặt ngưỡng CV thời gian đúng bằng kết nối của Neris) rồi tuyên bố detector đạt 100% Accuracy. Quy tắc phát hiện phải dựa trên nguyên lý hành vi tổng quát.
2. **Minh bạch về bằng chứng:** Mọi kết luận "Độc hại" hay "C2" bắt buộc phải đi kèm Frame number hoặc Flow UID có thể kiểm tra lại được trong Wireshark hoặc Zeek.
