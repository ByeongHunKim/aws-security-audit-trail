import json
from event_monitor_utils.base import BaseHandler

def lambda_handler(event, context):
    handler = BaseHandler()
    handler.logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event['detail']
        event_time = handler.convert_to_kst(event['time'])
        
        # Extract user identity details
        user_identity = detail.get('userIdentity', {})
        user_type = user_identity.get('type', 'Unknown')
        user_name = user_identity.get('userName', 'Unknown')
        
        response_elements = detail.get('responseElements', {})
        additional_data = detail.get('additionalEventData', {})
        
        login_result = response_elements.get('ConsoleLogin', 'Unknown')
        mfa_used = additional_data.get('MFAUsed', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        
        # Build user identifier
        user_identifier = "Root account" if user_type == "Root" else f"IAM user ({user_name})"
        
        # Create Slack message
        mention = "<!channel> " if (not handler.is_allowed_ip(source_ip)) else ""
        slack_message = handler.create_base_slack_message(
            f"Login detected - {user_identifier} {login_result} from {source_ip}",
            mention
        )
        
        # Add fields
        fields = {
            "Account Type": user_type,
            "User Name": user_name,
            "MFA Used": mfa_used,
            "Access IP": source_ip,
            "Event Time": event_time
        }
        handler.add_fields_to_message(slack_message, fields)
        
        # Set message color
        slack_message["attachments"][0]["color"] = "#eb4034" if user_type == "Root" else "#0c3f7d"
        
        # Send message
        handler.send_slack_message(slack_message)
        return {'statusCode': 200}
        
    except Exception as e:
        handler.logger.error(f"Error processing event: {str(e)}")
        handler.logger.error(f"Event: {json.dumps(event)}")
        raise
