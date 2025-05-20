import json
from event_monitor_utils.base import BaseHandler

class EC2Handler(BaseHandler):
    def get_event_description(self, event_name, request_params):

        if event_name == 'CreateInstanceConnectEndpoint':
            subnet_id = request_params.get('CreateInstanceConnectEndpointRequest', {}).get('SubnetId', 'N/A')
            return f"New Instance Connect Endpoint created for subnet '{subnet_id}'"
            
        descriptions = {
            'EnableHttpEndpoint': f"IMDS HTTP endpoint enabled for resource '{request_params.get('resourceId', 'N/A')}'",
            'OpenTunnel': f"SSH tunnel opened to instance '{request_params.get('instanceId', 'N/A')}'",
            'SendSSHPublicKey': f"SSH public key sent for instance '{request_params.get('instanceId', 'N/A')}'"
        }
        
        if event_name == 'AuthorizeSecurityGroupIngress':
            return self._format_security_group_description(request_params, "added")
        elif event_name == 'RevokeSecurityGroupIngress':
            return self._format_security_group_description(request_params, "removed")
            
        return descriptions.get(event_name, f"EC2 event {event_name} performed")
    
    def _format_security_group_description(self, params, action):
        group_id = params.get('groupId', 'N/A')
        ip_permissions = params.get('ipPermissions', {}).get('items', [])
        
        rules = []
        
        if not ip_permissions:
            return f"Security group '{group_id}' ingress rules {action}"
            
        for perm in ip_permissions:
            protocol = perm.get('ipProtocol', 'N/A')
            from_port = perm.get('fromPort', 'N/A')
            to_port = perm.get('toPort', 'N/A')
            
            ranges = []
            ip_ranges = perm.get('ipRanges', {}).get('items', [])
            for ip_range in ip_ranges:
                cidr = ip_range.get('cidrIp', 'N/A')
                desc = ip_range.get('description', '')
                ranges.append(f"{cidr} ({desc})" if desc else cidr)
                
            port_range = f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
            rules.append(f"{protocol} {port_range} from {', '.join(ranges)}")
            
        return f"Security group '{group_id}' ingress rules {action}: {'; '.join(rules)}"

    def is_high_risk_event(self, event_name, source_ip, request_params):
        # Check if it's from unallowed IP
        if not self.is_allowed_ip(source_ip):
            return True
            
        # High risk events based on type and parameters
        if event_name == 'AuthorizeSecurityGroupIngress':
            ip_permissions = request_params.get('ipPermissions', {}).get('items', [])
            for perm in ip_permissions:
                ip_ranges = perm.get('ipRanges', {}).get('items', [])
                for ip_range in ip_ranges:
                    if ip_range.get('cidrIp') == '0.0.0.0/0':
                        return True
                        
        # SSH related events are considered high risk
        if event_name in ['OpenTunnel', 'SendSSHPublicKey']:
            return True
            
        return False

def lambda_handler(event, context):
    handler = EC2Handler()
    handler.logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event['detail']
        event_name = detail['eventName']
        event_time = handler.convert_to_kst(event['time'])
        
        # Extract event details
        user_identity = detail.get('userIdentity', {})
        request_params = detail.get('requestParameters', {})
        error_code = detail.get('errorCode')
        error_message = detail.get('errorMessage')
        
        # Get user info
        user_type = user_identity.get('type', 'Unknown')
        user_name = user_identity.get('userName', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        
        # Get event description and determine risk
        description = handler.get_event_description(event_name, request_params)
        is_high_risk = handler.is_high_risk_event(event_name, source_ip, request_params)
        
        # Create mention based on risk
        mention = "<!channel> " if is_high_risk else ""
        
        # Add error information to description if present
        if error_code:
            description = f"{description} (Failed - {error_code}: {error_message})"
        
        # Create base message
        slack_message = handler.create_base_slack_message(
            f"EC2 Security Alert: {description}",
            mention
        )
        
        # Add fields
        fields = {
            "Event Type": event_name,
            "Initiated By": f"{user_type} ({user_name})",
            "Source IP": source_ip,
            "Event Time": event_time
        }
        
        # Add event specific fields
        if event_name in ['OpenTunnel', 'SendSSHPublicKey']:
            fields["Target Instance"] = request_params.get('instanceId', 'N/A')
        elif event_name == 'CreateInstanceConnectEndpoint':
            vpc_id = detail.get('responseElements', {}).get('CreateInstanceConnectEndpointResponse', {}).get('instanceConnectEndpoint', {}).get('vpcId', 'N/A')
            fields["VPC ID"] = vpc_id
        
        handler.add_fields_to_message(slack_message, fields)
        
        # Add request parameters for additional context
        slack_message["attachments"][0]["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Details:*\n```{json.dumps(request_params, indent=2)}```"
            }
        })
        
        # Set message color based on risk
        slack_message["attachments"][0]["color"] = "#FF0000" if is_high_risk else "#0c3f7d"
        
        # Send message
        handler.send_slack_message(slack_message)
        return {'statusCode': 200}
        
    except Exception as e:
        handler.logger.error(f"Error processing event: {str(e)}")
        handler.logger.error(f"Event: {json.dumps(event)}")
        raise
