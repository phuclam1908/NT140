# Bàn giao đề xuất cho Lâm – Evaluation gate (NT140 Week 2)

## Kết quả đã được xác nhận qua terminal của Quý

- 1.377 HTTP transactions từ Neris; 52 T1571, 69 T1071.001, 16 T1105 (137 rule hits); 122 distinct transactions alerted (15 double-rule), 1.255 không cảnh báo.
- T1105 có 16 file MIME candidates với 16 FUID matching files.log, seen=total/missing=0/overflow=0/timedout=False/is_orig=False.
- Hai responses `/p/out/kp.exe` có request frames 171 và 60845; response frames 251 và 60954; TCP streams 3 và 3265, HTTP 200, Content-Length 55808, HTTP body prefix `4d5a`.

## Quyết định Lâm cần review (chưa chốt)

1. Đơn vị metric: HTTP transaction hay Zeek connection hay Argus flow? Tách *unit of alert* và *unit of ground truth*; tránh đếm 1:n hai lần.
2. Chính sách nhãn: `From-Botnet` (positive candidate), `From-Normal` (negative candidate). `Background` và các biến thể không mặc định benign. Các nhãn botnet attempt cần định nghĩa phạm vi hành vi dự đoán.
3. Nhãn chỉ được sử dụng khi matching có chất lượng được phê duyệt. `overlap_association_only`, `ambiguous`, `unmatched` phải được xử lý minh bạch, không âm thầm loại mẫu rồi báo metrics chung.
4. Tập negative/benign phù hợp phải có **cùng đầu vào quan sát được** (HTTP/Zeek logs), tránh dùng full-payload PCAP của infected host so với CTU-13 normal flows không có payload.
5. Tách development/test và báo cáo giới hạn: rules đã được kiểm tra trên Neris, không coi kết quả này là hiệu quả khái quát; thử scenario 5/13 chỉ khi kiểm tra được nhãn và data model.

**Mục tiêu bước kế tiếp**: review `http_argus_alignment_review.csv` và `http_argus_alignment_summary.json`, quyết định cohort nào được chấm điểm và điều kiện metric hợp lệ. **Chưa có confusion matrix.**
