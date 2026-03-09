# 🧠 Kiến trúc Nội bộ: AWS Serverless SOAR

Hệ thống này triển khai luồng **Điều phối Dựa trên Quyết định (Decision-Based Orchestration)**, vượt xa các quy tắc tĩnh đơn giản để tiến tới đánh giá rủi ro thông minh.

## 1. Các thành phần cốt lõi

*   **GuardDuty & CloudTrail:** Nguồn dữ liệu cung cấp các phát hiện bảo mật và nhật ký kiểm tra API.
*   **Lớp Tình báo (Multi-Intel):**
    *   **VirusTotal:** Tổng hợp báo cáo từ ~70 công cụ diệt mã độc và sandbox để kiểm tra uy tín IP.
    *   **AbuseIPDB:** Báo cáo thời gian thực từ cộng đồng về các hoạt động brute-force, botnet và quét lỗ hổng.
*   **Bộ não: Scoring Engine (Bộ máy chấm điểm):**
    *   Tính toán động `risk_score` (0-100) dựa trên độ tin cậy của tình báo, mức độ nghiêm trọng của phát hiện và bối cảnh lịch sử.
    *   Đưa ra `decision` (quyết định): `IGNORE` (Bỏ qua), `REQUIRE_APPROVAL` (Cần phê duyệt), hoặc `AUTO_ISOLATE` (Tự động cách ly).
*   **Lambda Responders:** Các hàm Python xử lý thực thi các kịch bản phản ứng (playbooks) dựa trên quyết định của bộ máy chấm điểm.
*   **Tích hợp:** Tự động tạo ticket **Jira** và cảnh báo qua **SNS** để con người có thể giám sát.

## 2. Luồng Phản ứng Nâng cao

1.  **Làm giàu dữ liệu (Enrichment):** Khi nhận cảnh báo, hệ thống ngay lập tức truy vấn nhiều nguồn Tình báo mối đe dọa.
2.  **Chấm điểm (Scoring):** **Scoring Engine** đánh giá dữ liệu.
    *   Rủi ro thấp -> **Ghi log & Bỏ qua**.
    *   Rủi ro trung bình -> **Gửi cảnh báo (Chờ phê duyệt)**.
    *   Rủi ro cao (VD: IP đã xác nhận độc hại) -> **Tự động khóa lockdown**.
3.  **Xử lý (Auto-Isolate):**
    *   **Cách ly mạng:** Khóa chặt các Security Group.
    *   **Thu hồi quyền:** Vô hiệu hóa các khóa IAM ngay lập tức.
    *   **Thu thập chứng cứ:** Chụp Snapshot EBS để phục vụ điều tra pháp y.
4.  **Kiểm tra:** Toàn bộ lịch sử xử lý được gửi lên Jira kèm theo các báo cáo Tình báo để đối soát.

## 3. Tại sao lại dùng Serverless?
*   **Tiết kiệm:** Bạn không phải trả tiền nuôi con Robot này hàng tháng. Nó chỉ tốn tiền trong vài giây khi nó thực sự làm việc.
*   **Tốc độ:** Nó phản ứng trong mili giây, nhanh hơn con người rất nhiều.

---
**Tóm lại:** Bạn không cần phải hiểu mọi dòng code phức tạp. Chỉ cần hiểu luồng hoạt động này, bạn có thể tự tin thuyết phục bất kỳ ai về sức mạnh của dự án! 🚀
