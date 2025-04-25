import json
from event_monitor_utils.base import BaseHandler

class RDSHandler(BaseHandler):
    def get_event_description(self, event_name, request_params):
        if event_name == 'EnableHttpEndpoint':
            resource_arn = request_params.get('resourceArn', 'N/A')
            return f"HTTP Endpoint enabled for RDS resource: {resource_arn}"
            
        return f"RDS event {event_name} performed"

def lambda_handler(event, context):
    handler = RDSHandler()
    handler.logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event['detail']
        event_name = detail['eventName']
        event_time = handler.convert_to_kst(event['time'])
        
        user_identity = detail.get('userIdentity', {})
        request_params = detail.get('requestParameters', {})
        error_code = detail.get('errorCode')
        error_message = detail.get('errorMessage')
        
        user_type = user_identity.get('type', 'Unknown')
        user_name = user_identity.get('userName', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        
        description = handler.get_event_description(event_name, request_params)
        mention = "<!channel> "  # HTTP Endpoint 활성화는 항상 채널 멘션
        
        if error_code:
            description = f"{description} (Failed - {error_code}: {error_message})"
        
        slack_message = handler.create_base_slack_message(
            f"RDS Security Alert: {description}",
            mention
        )
        
        fields = {
            "Event Type": event_name,
            "Initiated By": f"{user_type} ({user_name})",
            "Source IP": source_ip,
            "Event Time": event_time,
            "Target Resource": request_params.get('resourceArn', 'N/A')
        }
        
        handler.add_fields_to_message(slack_message, fields)
        
        slack_message["attachments"][0]["color"] = "#FF0000"  # High risk event
        
        handler.send_slack_message(slack_message)
        return {'statusCode': 200}
        
    except Exception as e:
        handler.logger.error(f"Error processing event: {str(e)}")
        handler.logger.error(f"Event: {json.dumps(event)}")
        raise
