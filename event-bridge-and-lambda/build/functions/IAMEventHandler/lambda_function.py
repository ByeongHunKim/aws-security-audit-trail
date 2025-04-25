import json
from event_monitor_utils.base import BaseHandler

class IAMHandler(BaseHandler):
    def get_event_description(self, event_name, request_params):
        descriptions = {
            'CreateUser': f"New IAM user '{request_params.get('userName', 'N/A')}' created",
            'DeleteUser': f"IAM user '{request_params.get('userName', 'N/A')}' deleted",
            'AddUserToGroup': f"User '{request_params.get('userName', 'N/A')}' added to group '{request_params.get('groupName', 'N/A')}'",
            'RemoveUserFromGroup': f"User '{request_params.get('userName', 'N/A')}' removed from group '{request_params.get('groupName', 'N/A')}'",
            'AttachUserPolicy': f"Policy '{request_params.get('policyArn', 'N/A')}' attached to user '{request_params.get('userName', 'N/A')}'",
            'AttachGroupPolicy': f"Policy '{request_params.get('policyArn', 'N/A')}' attached to group '{request_params.get('groupName', 'N/A')}'",
            'CreateAccessKey': f"New access key created for user '{request_params.get('userName', 'N/A')}'",
            'DeleteAccessKey': f"Access key deleted for user '{request_params.get('userName', 'N/A')}'",
            'UpdateAccountPasswordPolicy': "Account password policy has been modified"
        }
        return descriptions.get(event_name, f"IAM event {event_name} performed")

def lambda_handler(event, context):
    handler = IAMHandler()
    handler.logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event['detail']
        event_name = detail['eventName']
        event_time = handler.convert_to_kst(event['time'])
        
        # Extract event details
        user_identity = detail.get('userIdentity', {})
        request_params = detail.get('requestParameters', {})
        
        # Get user info
        user_type = user_identity.get('type', 'Unknown')
        user_name = user_identity.get('userName', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        
        # Get event description and create message
        description = handler.get_event_description(event_name, request_params)
        mention = "<!channel> " if (not handler.is_allowed_ip(source_ip)) else ""
        
        # Create base message
        slack_message = handler.create_base_slack_message(
            f"IAM Security Alert: {description}",
            mention
        )
        
        # Add fields
        fields = {
            "Event Type": event_name,
            "Initiated By": f"{user_type} ({user_name})",
            "Source IP": source_ip,
            "Event Time": event_time
        }
        handler.add_fields_to_message(slack_message, fields)
        
        # Add request parameters details
        slack_message["attachments"][0]["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Details:*\n```{json.dumps(request_params, indent=2)}```"
            }
        })
        
        # Send message
        handler.send_slack_message(slack_message)
        return {'statusCode': 200}
        
    except Exception as e:
        handler.logger.error(f"Error processing event: {str(e)}")
        handler.logger.error(f"Event: {json.dumps(event)}")
        raise
