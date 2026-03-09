# 🧠 Cách thức hoạt động: AWS Serverless SOAR (Bản đơn giản)

Chào bạn! Nếu bạn cảm thấy hệ thống này quá phức tạp, hãy tưởng tượng nó giống như một **Hệ thống An ninh Tòa nhà thông minh**.

## 1. Các thành phần chính (Vai diễn)

*   **GuardDuty (Người Bảo Vệ AI):** Đây là con mắt 24/7. Nó không chỉ nhìn, nó còn "ngửi" thấy mùi nguy hiểm. Nếu nó thấy một máy tính (EC2) đang gởi dữ liệu cho hội đào tiền ảo (Crypto Miner), nó sẽ hét lên: "Finding!".
*   **EventBridge (Chuông báo động):** Khi GuardDuty hét lên, EventBridge sẽ bắt lấy tín hiệu đó và chuyển đến đúng nơi cần xử lý.
*   **Lambda Function (Cảnh sát phản ứng nhanh):** Đây là nơi chứa bộ não xử lý (Code Python). Khi nhận được báo động, nó sẽ thức dậy ngay lập tức để ngăn chặn cuộc tấn công.
*   **SNS/Jira/Slack (Đội thông tin):** Sau khi xử lý xong, nó sẽ báo cáo cho bạn biết chuyện gì đã xảy ra.

## 2. Quy trình xử lý khi có "Trộm" (Từng bước)

1.  **Phát hiện (Detect):** Hacker cài mã độc vào máy EC2 của bạn. GuardDuty phát hiện hành vi gởi dữ liệu ra các hồ đào tiền ảo.
2.  **Thông báo (Route):** Cảnh báo được đưa vào hàng đợi **SQS** để đảm bảo không tin nhắn nào bị mất, kể cả khi có hàng nghìn vụ tấn công cùng lúc.
3.  **Hành động (Remediate):** Lambda "Robot" thực hiện 4 việc trong vòng chưa đầy 30 giây:
    *   **Isolation (Cách ly):** Đổi Security Group về "Deny All". Giống như nhốt kẻ trộm vào phòng kín, cắt hết điện nước và mạng.
    *   **Snapshot (Lưu bằng chứng):** Chụp ảnh ổ cứng (EBS Snapshot). Đây là bằng chứng pháp y để bạn điều tra sau này.
    *   **Revoke (Hủy quyền):** Thu hồi ngay lập tức các quyền AWS (IAM Role) mà máy đó đang có, ngăn hacker dùng nó để phá hoại các dịch vụ khác.
    *   **Stop (Dừng máy):** Tắt máy luôn để tiết kiệm tiền và dừng mã độc.
4.  **Báo cáo (Report):** Hệ thống tự động tạo **Jira Ticket** và bắn tin nhắn **Slack**. Sáng ra bạn chỉ cần kiểm tra báo cáo: "Mối đe dọa đã được xử lý, đây là bằng chứng."

## 3. Tại sao lại dùng Serverless?
*   **Tiết kiệm:** Bạn không phải trả tiền nuôi con Robot này hàng tháng. Nó chỉ tốn tiền trong vài giây khi nó thực sự làm việc.
*   **Tốc độ:** Nó phản ứng trong mili giây, nhanh hơn con người rất nhiều.

---
**Tóm lại:** Bạn không cần phải hiểu mọi dòng code phức tạp. Chỉ cần hiểu luồng hoạt động này, bạn có thể tự tin thuyết phục bất kỳ ai về sức mạnh của dự án! 🚀
