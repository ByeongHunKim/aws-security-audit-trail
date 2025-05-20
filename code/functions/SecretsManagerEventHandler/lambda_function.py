import json
from event_monitor_utils.base import BaseHandler

class SecretsManagerHandler(BaseHandler):
    def get_event_description(self, event_name, request_params):
        descriptions = {
            'CreateSecret': "New secret created",
            'UpdateSecret': "Secret was updated",
            'DeleteSecret': "Secret was deleted",
            'GetSecretValue': "Secret value was retrieved",
            'BatchGetSecretValue': "Multiple secret values were retrieved",
            'RestoreSecret': "Secret was restored",
            'PutResourcePolicy': "Resource policy was modified for secret",
            'DeleteResourcePolicy': "Resource policy was removed from secret",
            'RotateSecret': "Manual rotation triggered for secret",
            'PutRotationSchedule': "Rotation schedule modified for secret",
            'ListSecrets': "List of secrets was retrieved"
        }
        return descriptions.get(event_name, f"Secrets Manager event {event_name} performed")

def lambda_handler(event, context):
    handler = SecretsManagerHandler()
    
    try:
        detail = event['detail']
        event_name = detail['eventName']
        event_time = handler.convert_to_kst(event['time'])
        
        user_identity = detail.get('userIdentity', {})
        request_params = detail.get('requestParameters', {})
        
        # 사용자 정보 추출 로직 개선
        user_type = user_identity.get('type', 'Unknown')
        user_name = user_identity.get('userName', 'Unknown')
        access_key = user_identity.get('accessKeyId', '')
        invoked_by = user_identity.get('invokedBy', '')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        
        # 사용자 표시 방식 개선
        if access_key:
            user_name = f"{user_name} (AccessKey: {access_key})"
        elif invoked_by:
            user_name = f"{user_name} (invoked by {invoked_by})"
        
        description = handler.get_event_description(event_name, request_params)
        
        high_risk_operations = ['DeleteSecret', 'PutResourcePolicy', 'DeleteResourcePolicy']
        
        mention = "<!channel> " if (event_name in high_risk_operations or not handler.is_allowed_ip(source_ip)) else ""
        
        slack_message = handler.create_base_slack_message(
            f"Secrets Manager Security Alert: {description}",
            mention
        )
        
        fields = {
            "Event Type": event_name,
            "Initiated By": f"{user_type} ({user_name})",
            "Source IP": source_ip,
            "Event Time": event_time
        }
        handler.add_fields_to_message(slack_message, fields)
        
        safe_params = request_params.copy()
        if 'ClientRequestToken' in safe_params:
            del safe_params['ClientRequestToken']
        if 'SecretString' in safe_params:
            safe_params['SecretString'] = '[REDACTED]'
        if 'SecretBinary' in safe_params:
            safe_params['SecretBinary'] = '[REDACTED]'
        
        # Error 정보가 있는 경우 추가
        if 'errorCode' in detail:
            safe_params['error'] = {
                'code': detail['errorCode'],
                'message': detail.get('errorMessage', 'No message')
            }
            
        slack_message["attachments"][0]["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Details:*\n```{json.dumps(safe_params, indent=2)}```"
            }
        })
        
        handler.send_slack_message(slack_message)
        return {'statusCode': 200}
        
    except Exception as e:
        handler.logger.error(f"Error processing event: {str(e)}")
        handler.logger.error(f"Event: {json.dumps(event)}")
        raise
