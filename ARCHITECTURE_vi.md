# 🧠 Kiến trúc Nội bộ: AWS Serverless SOAR

Hệ thống này triển khai luồng **Điều phối Dựa trên Quyết định** với tình báo đa tầng, phát hiện bất thường AI/ML, và chiến lược cách ly chi tiết.

## 1. Các thành phần cốt lõi

*   **Tầng phát hiện (GuardDuty, CloudTrail, Security Hub, Inspector, Macie, VPC Flow Logs):** Nguồn dữ liệu cung cấp các phát hiện bảo mật và nhật ký kiểm tra API thời gian thực.
*   **Tầng Tình báo & Chấm điểm:**
    *   **VirusTotal:** Tổng hợp báo cáo từ ~70 engine diệt mã độc để kiểm tra uy tín IP.
    *   **AbuseIPDB:** Báo cáo thời gian thực từ cộng đồng về các hoạt động brute-force, botnet và quét lỗ hổng.
    *   **Phát hiện bất thường ML (Isolation Forest):** Phân tích hành vi sử dụng feature vector (`hour_of_day`, `day_of_week`, `ip_reputation_score`, `action_risk_level`, `request_frequency`) với fallback Z-Score.
    *   **Scoring Engine (0-100):** Tính toán động `risk_score` kết hợp độ tin cậy tình báo, mức độ nghiêm trọng, và anomaly boost (+15). Đầu ra: `IGNORE (<40)`, `REQUIRE_APPROVAL (40-70)`, `AUTO_ISOLATE (>70)`.
*   **Nền tảng SOAR:**
    *   **Định tuyến sự kiện:** EventBridge → SQS (Buffer Queue + DLQ) để đảm bảo giao nhận.
    *   **Điều phối luồng:** Step Functions (State Machine) → Lambda (Isolation Worker) + Fargate/ECS (Forensic Worker).
    *   **Phê duyệt con người:** Tích hợp Slack/Jira cho quyết định human-in-the-loop.
    *   **Chuẩn hóa sự kiện:** Chuyển đổi sự kiện native thành schema `UnifiedIncident` để tương thích đa nền tảng.
    *   **Tương quan sự cố:** Nhóm các cảnh báo liên quan theo IOC chung (IP, tác nhân, cửa sổ ±5 phút) để phát hiện chiến dịch tấn công đa giai đoạn.
*   **Hệ thống phân cấp cách ly (Function > Process > Permissions > Network):**
    *   **Tầng Process:** Kill các tiến trình độc hại và cách ly file qua SSM Run Command.
    *   **Tầng Permissions:** Vô hiệu hóa access key, thu hồi session, gắn policy DenyAll.
    *   **Tầng Network:** Cách ly instance qua Security Group lockdown (biện pháp cuối cùng).

## 2. Luồng Phản ứng

1.  **Làm giàu dữ liệu:** Khi nhận cảnh báo, hệ thống truy vấn nhiều nguồn Tình báo và chạy phát hiện bất thường ML.
2.  **Chấm điểm:** Scoring Engine đánh giá tất cả tín hiệu và tính risk score kèm anomaly boost.
    *   Rủi ro thấp → **Ghi log & Bỏ qua**.
    *   Rủi ro trung bình → **Gửi cảnh báo (Chờ phê duyệt con người)**.
    *   Rủi ro cao → **Tự động cách ly** (kill process → thu hồi quyền → cách ly mạng).
3.  **Xử lý:**
    *   **Cách ly Process:** Kill các tiến trình nghi ngờ (xmrig, cryptominer) qua SSM.
    *   **Thu hồi quyền:** Vô hiệu hóa khóa IAM, thu hồi session.
    *   **Cách ly mạng:** Khóa chặt Security Group.
    *   **Thu thập chứng cứ:** Chụp Snapshot EBS cho điều tra số.
4.  **Kiểm toán & Tuân thủ:** Tất cả hành động được ghi vào audit trail bất biến (CloudWatch Logs → S3). Lịch sử đầy đủ gửi lên Jira để đối soát.

## 3. Quan sát & Gia cố Bảo mật

*   **CloudWatch Dashboard (Terraform):** Lượng sự cố, tỷ lệ lỗi, MTTR, độ sâu SQS, trạng thái Step Functions, SLO/SLI.
*   **CloudWatch Alarms:** Tự động cảnh báo khi Lambda lỗi hoặc DLQ tồn đọng.
*   **Xoay vòng bí mật:** Chính sách xoay 90 ngày cho tất cả API key qua SSM Parameter Store.
*   **Audit Logger:** Nhật ký kiểm toán có cấu trúc cho mọi hành động SOAR với CloudWatch + S3 lưu trữ.

## 4. Tại sao Serverless?
*   **Tiết kiệm:** Không phải trả tiền khi nhàn rỗi. Chi phí chỉ ~$5-15/tháng với lưu lượng vừa phải.
*   **Tốc độ:** Phản ứng trong mili giây, nhanh hơn bất kỳ nhân viên vận hành nào.
*   **Mở rộng:** Dù 1 hay 1.000 sự cố, AWS tự mở rộng Lambda và Fargate để xử lý đồng thời.

---
**Tóm lại:** Một "Hạ tầng Tự chữa lành" với tình báo đa tầng, phát hiện bất thường ML, và cách ly chi tiết — từ kill một tiến trình đến cách ly toàn bộ mạng. 🚀
