# NT140 / Scenario 01 — T1105 packet-level evidence addendum

**Status:** Observed and packet-checked for two HTTP response bodies; no claim of full PE structural validation, on-disk persistence, execution, or maliciousness based on MIME/MZ alone.

- Dataset: CTU-13 S01/Neris. Neris origination `147.32.84.165`; destination `60.190.223.75:2012/TCP`; HTTP Host `shabi.coolnuff.com:2012`; request URI `/p/out/kp.exe`.
- First transaction: Zeek UID `CKUYcz36QpcqpNvRi4`, FUID `FcEd4y1UfNvlHok7h9`, request frame **171**, HTTP response frame **251**, TCP stream **3**, 2011-08-10 09:06:38.707651 UTC request.
- Second transaction: Zeek UID `CL9KnbLVkdBhZW9Pi`, FUID `FvQfdj2TWQsMk212d4`, request frame **60845**, response frame **60954**, TCP stream **3265**, request at 2011-08-10 10:10:08.674689 UTC.
- Both HTTP responses: status `200`, `Content-Type: application/octet-stream`, `Content-Length: 55808`. Zeek identified MIME `application/x-dosexec` in `http.log`/`files.log`. Zeek `files.log`: `is_orig=False`, `seen_bytes=total_bytes=55808`, `missing_bytes=0`, `overflow_bytes=0`, `timedout=False` for both FUIDs.
- TShark direct response body prefix at frame 251 and 60954: `4d5a90000300000004000000ffff0000b8000000000000004000000000000000`. The first two bytes `4D 5A` spell `MZ`.
- The same length and 32-byte prefix do NOT prove that both full response bodies are identical. Verifying a full PE requires further header checking (e.g., `PE\0\0` at `e_lfanew`); no file execution evidence is available from PCAP alone.
- Technical classification: **packet-supported executable-like HTTP content transfer**. ATT&CK T1105 is a hypothesis/analyst mapping until incident context and ground truth support classification.

## Reproduction (read-only)

```bash
cd ~/NT140
PCAP="$PWD/data/raw/scenario-01-neris/pcap/botnet-capture-20110810-neris.pcap"
cat "$PCAP" | tshark -r - -d tcp.port==2012,http \
  -Y '(tcp.stream == 3 || tcp.stream == 3265) && http.response' \
  -T fields -e frame.number -e tcp.stream -e http.response.code \
  -e http.content_length -e http.content_type

cat "$PCAP" | tshark -r - -d tcp.port==2012,http \
  -Y '(tcp.stream == 3 || tcp.stream == 3265) && http.file_data' \
  -T fields -e frame.number -e tcp.stream -e http.file_data \
  | awk -F '\t' '{printf "frame=%s stream=%s prefix=%s\n",$1,$2,substr($3,1,64)}'
```

Do not extract or execute the payload. Screenshots, if collected by a teammate, must cite the frame/stream above.
