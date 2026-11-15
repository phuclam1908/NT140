# NT140 — Week 2 / Quý — T1105 executable-response evidence review

**Trạng thái:** Preliminary candidate, chưa xác nhận ground truth, MZ raw bytes, file completeness hay thực thi.  
**Dataset:** CTU-13 Scenario 1 / Neris, infected IP `147.32.84.165`.  
**Nguồn:** Zeek 9.0.1 JSON logs trên Ubuntu VM, người dùng cung cấp terminal output ngày 09/11/2026.

## Kết quả được ghi nhận từ terminal (chưa phải output của script T1105 mới)

Hai HTTP transactions từ Neris tới `shabi.coolnuff.com:2012`, URI `/p/out/kp.exe`:

| Zeek UID | HTTP method | status | response_body_len | resp_mime_types |
|---|---|---:|---:|---|
| `CKUYcz36QpcqpNvRi4` | GET | 200 | 55,808 | `application/x-dosexec` |
| `CL9KnbLVkdBhZW9Pi` | GET | 200 | 55,808 | `application/x-dosexec` |

Hai response có tổng **111,616 bytes theo giá trị `response_body_len`**, nhưng không thể suy ra đây là hai file khác nhau hay hai bản sao được máy nạn nhân lưu thành công. `resp_mime_types` là loại tệp Zeek nhận diện qua phân tích lưu lượng, **không tự động tương đương HTTP `Content-Type` header**, cũng không tự thay cho kiểm tra byte `MZ` (`4D 5A`) trên packet.

## Phương pháp detector

`src/detection/executable_ingress_detector.py` đọc `conn.log`, `http.log`, `files.log` (nếu có, phải cùng Zeek run). Ghép HTTP bằng `uid`, ghép file analysis bằng `resp_fuids` → `files.log.fuid`. Chỉ tạo ứng viên khi HTTP status 2xx và response body > 0, cộng với (i) PE-like MIME được Zeek nhận diện, hoặc (ii) URI có đuôi executable-like (`.exe/.dll/.scr/.sys`).

Output của rule là **network executable-response candidates** liên quan giả thuyết MITRE ATT&CK **T1105**, không phải kết luận malware/tool transfer được xác thực. Trường hợp chỉ có đuôi URI mang mức bằng chứng thấp hơn PE-like MIME.

## Chạy và kiểm tra

```bash
cd ~/NT140
source .venv/bin/activate
python -m py_compile src/detection/executable_ingress_detector.py
PYTHONPATH=src/detection python -m unittest discover -s tests -p 'test_executable_ingress_detector.py' -v
python src/detection/executable_ingress_detector.py --repo "$PWD"
python - <<'PY'
import pandas as pd
p = 'reports/week2/quy/generated/executable_ingress_candidates.csv'
d = pd.read_csv(p)
print(d[['dst_ip','dst_port','http_host','uri_path',
         'http_request_count','pe_mime_transaction_count',
         'reported_response_body_bytes_sum','sample_zeek_uids']].to_string(index=False))
PY
```

Các file xuất ra:

- `reports/week2/quy/generated/executable_ingress_events.csv`: mỗi HTTP transaction là một bản ghi, có Zeek UID/FUID.
- `reports/week2/quy/generated/executable_ingress_candidates.csv`: gộp theo destination IP/port, protocol, HTTP Host và URI path.

Không commit `generated` nếu `.gitignore` quy định loại trừ.

## Review tiếp theo với Thương / Thi / Lâm

1. Dùng Wireshark mở PCAP, lọc `ip.addr == 147.32.84.165 && ip.addr == 60.190.223.75 && tcp.port == 2012` (nếu IP đích thực tế không như giả định, lấy từ `executable_ingress_events.csv` trước). Decode As HTTP nếu cần.
2. Xác minh response body sau HTTP headers, hai byte đầu file nếu quan sát được (`4D 5A` / `MZ`), `Content-Length`, TCP gaps, retransmission, và số byte thực sự quan sát.
3. Kiểm tra trong `files.log` bằng FUID liên kết; `seen_bytes`, `total_bytes`, `missing_bytes` giúp đánh giá chất lượng capture, nhưng không chứng minh file đã được ghi trên đĩa endpoint.
4. Chỉ nâng lên `packet-validated` khi có frame/stream evidence, và chỉ ghi `dataset-labeled` sau khi đối chiếu chính xác từng đơn vị record với CTU-13 Argus flows. Không tự gán TP/FP.
5. Không ghi đè FND-001/002/003 hiện có: bản kế hoạch tuần 2 đánh số finding khác handoff tuần 1. Chốt mã ID với nhóm trước khi tạo FND mới.

## Bối cảnh Rule 1/2 đã chạy thực tế

- **T1571 hypothesis**: 52 HTTP requests trên port ngoài 80/443/8080, **27 groups** (candidate).
- **T1071.001 hypothesis**: 3 groups từ 286 HTTP groups: `finalcortex.com` POST `/snapbn/gate.php` 53 requests, hai nhóm `/sn.php` 8 requests mỗi nhóm.
- `/snapbn/gate.php`: kết quả alignment tuần 1 là **53 direct Zeek–Argus pairs (1 GET + 52 POST)** của 54 HTTP connections đến endpoint, cùng **1 POST overlap association**; không biến 53 POST riêng lẻ thành 53 direct matched POSTs.
- Với `/snapbn/gate.php`, `burst_sizes=1;1;...` vì threshold phân đoạn 60 s thấp hơn IAT điển hình ~120–126 s; không mô tả là 53 đợt tấn công độc lập.

**Không đo Precision/Recall/F1/FPR** khi chưa chốt đơn vị đánh giá, label policy và xử lý Zeek–Argus 1:n cùng Lâm. Không coi CTU-13 `Background` là benign được xác nhận.
