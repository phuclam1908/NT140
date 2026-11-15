# CTU-13 Scenario 1 — Flow-label alignment notes (DQUY, week 1)

## Inputs and provenance
- Source: CTU-13 Scenario 1 / Neris, CTU-Malware-Capture-Botnet-42.
- Zeek 9.0.1 `conn.log` derived from public botnet-only PCAP (31,735 connections; 31,361 initiated by `147.32.84.165`).
- Argus `capture20110810.binetflow`: 2,824,636 bidirectional labeled flows; 40,961 `From-Botnet` and 30,258 `From-Normal` records; 41,270 rows have Neris as either source or destination.
- Do not assume Zeek connections and Argus flows have identical granularity or complete overlap. The public botnet PCAP is not a complete capture of benign/background traffic.

## Label categories
`Background`: 1,787,731; `To-Background`: 965,055; `From-Background`: 502; `From-Botnet`: 40,961; `From-Normal`: 30,258; `To-Normal`: 120; `Other/Unknown`: 9.

These are **source-derived prefixes**, not directly binary evaluation labels. `Background` and `To-Background` must not automatically be treated as verified benign. The nine `Other/Unknown` records need manual review.

## Time alignment hypothesis and preliminary evidence
- Convert Zeek Unix timestamps to UTC.
- Interpret Argus `StartTime` tentatively as local `Europe/Prague` time, then convert to UTC. This is supported by several matching endpoint/port records, but needs validation across more cases.
- After conversion: Zeek Neris connections span **2011-08-10 09:04:23.241037 UTC** to **13:48:48.887707 UTC**; Argus `From-Botnet` spans **09:04:24.863449 UTC** to **13:48:49.449944 UTC**.
- Example candidate: `147.32.84.165 → 31.192.109.167:80/TCP`; Zeek has **54** connections, Argus has **53** flows.
- First five records share source ports **1272, 1276, 1338, 1373, 1432** and have Argus minus Zeek start-time offsets of about **+0.459 seconds**.
- Corresponding Argus records display `flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted`.

## Interpretation for FND-001
The repeated HTTP POST finding targeting `finalcortex.com` has supporting source-dataset C&C labels. This is stronger than temporal-pattern evidence alone. Do **not** imply all 54 Zeek connections already have verified one-to-one label matches; investigate the 54-vs-53 difference.

## Matching method under test
1. Keep exact source/destination IP, protocol, source/destination port (check reverse direction separately if needed).
2. Convert both timestamps to UTC and measure offset.
3. Generate candidate matches within an exploratory time window; reject ambiguous matches rather than silently choosing one.
4. Evaluate time-offset distribution, connection duration, direction, duplicates and mismatches; distinguish **unmatched** from **unknown label**.
5. Confirm ground-truth joins on several protocols and endpoints before generalizing to the entire dataset.
6. Define the evaluation unit (connection, flow, endpoint or time window) jointly with Lâm before computing TP/FP/TN/FN or Precision/Recall/F1/FPR.

## Current status and next actions
- Verified: extraction, source label distribution, candidate time-zone interpretation supported by five matching HTTP-C2 sample flows.
- Pending: test all 54 HTTP connections; inspect unpaired record(s), review 9 unknown labels, extend alignment validation beyond one HTTP endpoint.
- Current classification of alignment: **candidate matches observed; full alignment not validated**.
- Handoff: Lâm — choose label/evaluation policy; Thi — C&C interpretation; Thương — packet/stream verification.

### HTTP C2 Flow Alignment Results

**Dataset:** CTU-13 Scenario 1 – Neris

**Endpoint:** `147.32.84.165 → 31.192.109.167:80/TCP`

Phép đối chiếu Zeek–Argus được thực hiện dựa trên source IP, destination IP, source port, destination port, protocol và timestamp đã chuyển đổi sang UTC.

Ngưỡng sai lệch thời gian được sử dụng trong thử nghiệm là ±2 giây.

**Kết quả:**
- Zeek connections: 54.
- Argus labeled flows: 53.
- Candidate pairs: 53.
- One-to-one unambiguous matches: 53.
- Unmatched Zeek connections: 1.
- Unmatched Argus flows: 0.
- Matching coverage trên Zeek connections: 98,15%.

Toàn bộ 53 cặp khớp có nhãn `flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted`.

Sai lệch timestamp trung bình giữa Argus và Zeek là 0,478152 giây, với độ lệch chuẩn 0,023491 giây.

Kết quả này cung cấp bằng chứng từ ground truth CTU-13 cho hoạt động HTTP Command & Control được ghi nhận trong Finding FND-001.

**Hạn chế:** Một Zeek connection có UID `CyX70D31uZteVKQKja` chưa có bản ghi Argus tương ứng theo phương pháp ghép hiện tại. Nguyên nhân chưa được xác định.

Việc đối chiếu thành công trên một endpoint không chứng minh thuật toán alignment hoạt động chính xác với mọi kết nối trong dataset. Phương pháp cần được đánh giá thêm trên các giao thức và nhóm traffic khác trước khi sử dụng để tính các chỉ số phát hiện.
### Investigation of Unmatched Zeek Connection

Trong quá trình đối chiếu HTTP C2 giữa Zeek và Argus, hệ thống ghi nhận 54 Zeek connections và 53 Argus flows.

Phương pháp ghép dựa trên 5-tuple kết hợp sai lệch thời điểm bắt đầu tối đa 2 giây đã xác định được 53 cặp khớp một-một. Toàn bộ 53 Argus flows này được gán nhãn `flow=From-Botnet-V42-TCP-CC53-HTTP-Not-Encrypted`.

Kết nối Zeek còn lại có các đặc điểm:

- UID: `CyX70D31uZteVKQKja`.
- Source: `147.32.84.165:2275`.
- Destination: `31.192.109.167:80/TCP`.
- Start time: `2011-08-10 10:31:25.469770 UTC`.
- Duration: 0,179690 giây.
- HTTP method: POST.
- HTTP URI: `/snapbn/gate.php`.
- HTTP status: 200.

Kiểm tra dữ liệu Argus cho thấy tồn tại một flow có cùng 5-tuple, bắt đầu lúc `10:12:54.604939 UTC` và kéo dài 1.111,622192 giây, kết thúc lúc `10:31:26.227131 UTC`.

Như vậy, thời gian của Zeek connection chưa khớp nằm trong khoảng thời gian của Argus flow.

Kết quả cho thấy kết nối không bị thiếu hoàn toàn thông tin tương ứng trong dữ liệu Argus. Vấn đề nằm ở sự khác biệt giữa thời điểm bắt đầu Zeek connection và Argus flow.

Một giả thuyết cần kiểm chứng là Argus đã tổng hợp hoạt động sử dụng cùng 5-tuple vào một flow dài, trong khi Zeek phân chia thành nhiều connections.

**Kết luận:** Phương pháp ghép một-một dựa trên thời điểm bắt đầu chưa xử lý đầy đủ các trường hợp có sự khác biệt về cách phân chia flow. Các bước tiếp theo cần xem xét khoảng thời gian tồn tại của flow, khả năng tái sử dụng 5-tuple và trường hợp một Argus flow tương ứng với nhiều Zeek connections.

Chưa áp dụng tự động nhãn của flow dài cho kết nối Zeek chưa ghép được trước khi xác minh mối quan hệ giữa các bản ghi.
