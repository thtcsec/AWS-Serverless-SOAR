output "target_ec2_public_ip" {
  description = "Public IP of your target vulnerable EC2 instance used for simulating attacks"
  value       = aws_instance.target_ec2.public_ip
}

output "target_ec2_id" {
  description = "Instance ID of the vulnerable EC2 instance"
  value       = aws_instance.target_ec2.id
}

output "guardduty_detector_id" {
  description = "GuardDuty Detector ID"
  value       = aws_guardduty_detector.detector.id
}

output "lambda_function_name" {
  description = "Name of the SOAR execution lambda function"
  value       = aws_lambda_function.soar_responder.function_name
}
