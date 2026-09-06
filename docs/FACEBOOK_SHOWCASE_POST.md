# Bài đăng Facebook — AWS Project Showcase

Copy toàn bộ phần dưới (từ emoji 🚀 đến hashtag cuối).  
Đính kèm ảnh: `images/master_architecture.png` + (tuỳ chọn) `images/aws_soar.png` hoặc screenshot evidence lab.

---

🚀 **AWS Serverless SOAR — Unified Incident Response Pipeline**

Mình share project thực tế mình đã build & chạy lab trên AWS: một nền tảng **SOAR serverless** tự động phản ứng sự cố bảo mật, không cần “bấm tay” từng bước khi GuardDuty/CloudTrail báo cáo.

## Vấn đề mình giải quyết
SOC thường nhận alert rời rạc, playbook phân mảnh, và sợ auto-remediate mù quáng. Mình gom mọi event vào **một pipeline duy nhất**, có **policy gate** trước khi containment.

## Kiến trúc (real, đang dùng)
```
GuardDuty / CloudTrail
        ↓
EventBridge (+ SQS buffer tùy chọn)
        ↓
Lambda → handlers.handle_event()
        ↓
Normalize → Correlate → Score → Decision → Playbook → Audit
```

Decision bands:
- **IGNORE** (&lt;40)
- **REQUIRE_APPROVAL** (40–69) → Slack, không auto
- **AUTO_ISOLATE** (≥70) → chạy playbook

## AWS services mình dùng
GuardDuty, CloudTrail, EventBridge, Lambda (Python 3.12), SQS/DLQ, IAM, EC2 (isolation SG + snapshot + stop), S3, SNS, CloudWatch, Terraform IaC.

Playbooks chính: EC2 Containment, S3 Exfiltration, IAM Compromise (+ EKS/RDS/API/CI-CD…).

## Điều mình học được (không phải tutorial copy)
1. **Không để business logic nằm trong Step Functions** — wiring legacy tách khỏi spine; hot path chỉ trong Lambda `IncidentPipeline`.
2. **Policy gate trước playbook** — auto isolate chỉ khi score đủ cao; mid-band bắt buộc người duyệt.
3. **Dry-run trước, live lab sau** — preview `planned_actions` rồi mới remediation trên EC2 lab.

## Repo + bằng chứng
🔗 GitHub: https://github.com/thtcsec/AWS-Serverless-SOAR  
(Kiến trúc multi-cloud cùng contract với GCP, nhưng bài này focus AWS.)

CI đang xanh (pytest + ruff). Lab đã deploy Terraform / invoke Lambda dry-run & containment thật trên instance lab.

Diagram đính kèm = master architecture UIRP (single pipeline).

Rất welcome anh/chị comment hỏi kiến trúc, scoring, hoặc cách mình tách legacy Step Functions — mình reply hết 🙌

#AWSVietnamRegion #AWSProjectShowcase #AWS #CloudComputing #SOAR #Serverless #GuardDuty #Terraform
