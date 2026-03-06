"""
Enterprise SOAR - Queue Processor Lambda
Processes SQS messages and triggers Step Functions workflows
"""

import json
import os
import boto3
from datetime import datetime
from datetime import timezone, timezone
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')))

def lambda_handler(event, context):
    """
    Process SQS messages and trigger appropriate workflows
    
    Expected input: SQS batch event
    Output: Processed messages and workflow executions
    """
    try:
        logger.info(f"Processing {len(event.get('Records', []))} SQS messages")
        
        step_function_client = boto3.client('stepfunctions')
        step_function_arn = os.environ.get('STEP_FUNCTION_ARN')
        dlq_url = os.environ.get('DLQ_URL')
        
        processed_messages = 0
        failed_messages = 0
        workflow_executions = []
        
        for record in event.get('Records', []):
            try:
                # Parse message body
                message_body = json.loads(record['body'])
                message_id = record['messageId']
                
                logger.info(f"Processing message {message_id}")
                
                # Validate message format
                if not validate_message(message_body):
                    logger.warning(f"Invalid message format for message {message_id}")
                    failed_messages += 1
                    continue
                
                # Determine event type and route to appropriate workflow
                event_type = message_body.get('event_type', '')
                event_source = message_body.get('event_source', '')
                
                if event_source == 'aws.guardduty':
                    execution_arn = trigger_guardduty_workflow(
                        step_function_client, 
                        step_function_arn, 
                        message_body
                    )
                    workflow_executions.append({
                        'message_id': message_id,
                        'execution_arn': execution_arn,
                        'workflow_type': 'guardduty_incident_response'
                    })
                    
                elif event_source == 'aws.iam':
                    execution_arn = trigger_iam_workflow(
                        step_function_client, 
                        step_function_arn, 
                        message_body
                    )
                    workflow_executions.append({
                        'message_id': message_id,
                        'execution_arn': execution_arn,
                        'workflow_type': 'iam_incident_response'
                    })
                    
                elif event_source == 'aws.s3':
                    execution_arn = trigger_s3_workflow(
                        step_function_client, 
                        step_function_arn, 
                        message_body
                    )
                    workflow_executions.append({
                        'message_id': message_id,
                        'execution_arn': execution_arn,
                        'workflow_type': 's3_incident_response'
                    })
                    
                else:
                    logger.warning(f"Unknown event source: {event_source}")
                    failed_messages += 1
                    continue
                
                processed_messages += 1
                logger.info(f"Successfully triggered workflow for message {message_id}")
                
            except Exception as e:
                logger.error(f"Error processing message {record.get('messageId', 'unknown')}: {str(e)}")
                failed_messages += 1
                
                # Send failed message to DLQ
                try:
                    send_to_dlq(record, dlq_url)
                except Exception as dlq_error:
                    logger.error(f"Failed to send message to DLQ: {str(dlq_error)}")
        
        # Build response
        response = {
            'processed_messages': processed_messages,
            'failed_messages': failed_messages,
            'total_messages': len(event.get('Records', [])),
            'workflow_executions': workflow_executions,
            'processing_timestamp': datetime.now(timezone.utc).isoformat(),
            'lambda_request_id': context.aws_request_id
        }
        
        logger.info(f"Queue processing complete: {processed_messages} processed, {failed_messages} failed")
        
        return response
        
    except Exception as e:
        logger.error(f"Critical error in queue processor: {str(e)}")
        raise e

def validate_message(message_body):
    """Validate message format and required fields"""
    required_fields = ['event_source', 'event_type', 'event_time']
    
    for field in required_fields:
        if field not in message_body:
            logger.warning(f"Missing required field: {field}")
            return False
    
    return True

def trigger_guardduty_workflow(sfn_client, sfn_arn, message):
    """Trigger GuardDuty incident response workflow"""
    try:
        # Transform message for Step Functions
        input_data = {
            'detail': message.get('finding', {}),
            'source': message.get('event_source'),
            'time': message.get('event_time'),
            'id': message.get('event_id'),
            'account': message.get('account'),
            'region': message.get('region'),
            'routing_timestamp': message.get('routing_timestamp')
        }
        
        # Start Step Function execution
        response = sfn_client.start_execution(
            stateMachineArn=sfn_arn,
            name=f"guardduty-{message.get('event_id', 'unknown')}-{int(datetime.now(timezone.utc).timestamp())}",
            input=json.dumps(input_data)
        )
        
        logger.info(f"Started GuardDuty workflow execution: {response['executionArn']}")
        return response['executionArn']
        
    except Exception as e:
        logger.error(f"Failed to trigger GuardDuty workflow: {str(e)}")
        raise

def trigger_iam_workflow(sfn_client, sfn_arn, message):
    """Trigger IAM incident response workflow"""
    try:
        # Transform message for Step Functions
        input_data = {
            'detail': message.get('event', {}),
            'source': message.get('event_source'),
            'time': message.get('event_time'),
            'id': message.get('event_id'),
            'account': message.get('account'),
            'region': message.get('region'),
            'routing_timestamp': message.get('routing_timestamp')
        }
        
        # Start Step Function execution
        response = sfn_client.start_execution(
            stateMachineArn=sfn_arn,
            name=f"iam-{message.get('event_id', 'unknown')}-{int(datetime.now(timezone.utc).timestamp())}",
            input=json.dumps(input_data)
        )
        
        logger.info(f"Started IAM workflow execution: {response['executionArn']}")
        return response['executionArn']
        
    except Exception as e:
        logger.error(f"Failed to trigger IAM workflow: {str(e)}")
        raise

def trigger_s3_workflow(sfn_client, sfn_arn, message):
    """Trigger S3 incident response workflow"""
    try:
        # Transform message for Step Functions
        input_data = {
            'detail': message.get('event', {}),
            'source': message.get('event_source'),
            'time': message.get('event_time'),
            'id': message.get('event_id'),
            'account': message.get('account'),
            'region': message.get('region'),
            'routing_timestamp': message.get('routing_timestamp')
        }
        
        # Start Step Function execution
        response = sfn_client.start_execution(
            stateMachineArn=sfn_arn,
            name=f"s3-{message.get('event_id', 'unknown')}-{int(datetime.now(timezone.utc).timestamp())}",
            input=json.dumps(input_data)
        )
        
        logger.info(f"Started S3 workflow execution: {response['executionArn']}")
        return response['executionArn']
        
    except Exception as e:
        logger.error(f"Failed to trigger S3 workflow: {str(e)}")
        raise

def send_to_dlq(record, dlq_url):
    """Send failed message to Dead Letter Queue"""
    try:
        sqs_client = boto3.client('sqs')
        
        # Add error information to message
        enhanced_message = {
            'original_message': json.loads(record['body']),
            'error_info': {
                'failed_timestamp': datetime.now(timezone.utc).isoformat(),
                'failure_reason': 'queue_processing_error',
                'original_message_id': record['messageId']
            }
        }
        
        sqs_client.send_message(
            QueueUrl=dlq_url,
            MessageBody=json.dumps(enhanced_message),
            MessageAttributes={
                'OriginalMessageId': {
                    'DataType': 'String',
                    'StringValue': record['messageId']
                },
                'FailureReason': {
                    'DataType': 'String',
                    'StringValue': 'queue_processing_error'
                }
            }
        )
        
        logger.info(f"Sent message {record['messageId']} to DLQ")
        
    except Exception as e:
        logger.error(f"Failed to send message to DLQ: {str(e)}")
        raise
