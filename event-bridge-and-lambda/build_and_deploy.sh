#!/bin/bash
# AWS Security Monitoring Deployment Script
# This script builds and deploys the AWS Security Monitoring solution

set -e

# Configuration
# todo make input
STACK_NAME="aws-security-monitoring"
PRIMARY_REGION="us-east-1"
SECONDARY_REGIONS=("ap-southeast-1") # Add additional regions as needed
# SLACK_WEBHOOK_URL=""
# ALLOWED_IPS="" # Comma-separated list of allowed IPs

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to check for required tools
check_prerequisites() {
  echo "Checking prerequisites..."
  
  command -v aws >/dev/null 2>&1 || { 
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}" >&2
    exit 1
  }
  
  command -v jq >/dev/null 2>&1 || { 
    echo -e "${YELLOW}Warning: jq is not installed. Some features may not work correctly.${NC}" >&2
  }
  
  # Check AWS CLI configuration
  aws sts get-caller-identity >/dev/null 2>&1 || {
    echo -e "${RED}Error: AWS CLI is not configured properly. Please run 'aws configure'.${NC}" >&2
    exit 1
  }
  
  echo -e "${GREEN}Prerequisites check passed.${NC}"
}

# Function to create directory structure
create_directories() {
  echo "Creating directory structure..."
  
  mkdir -p build/{functions,layers}
  mkdir -p build/layers/event_monitor_utils/{event_monitor_utils,python}
  
  echo -e "${GREEN}Directory structure created.${NC}"
}

# Function to build Lambda layer
build_layer() {
  echo "Building event-monitor-utils Lambda layer..."
  
  # Create __init__.py
  cat > build/layers/event_monitor_utils/event_monitor_utils/__init__.py << 'EOF'
from .base import BaseHandler
__all__ = ['BaseHandler']
EOF

  # Create base.py
  cat > build/layers/event_monitor_utils/event_monitor_utils/base.py << 'EOF'
import os
from datetime import datetime, timedelta
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import logging

class BaseHandler:
    def __init__(self):
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.hook_url = os.environ['HOOK_URL']
        self.allowed_ips = [ip.strip() for ip in os.environ['ALLOWED_IP'].split(',')]

    def is_allowed_ip(self, ip):
        return ip in self.allowed_ips

    def convert_to_kst(self, utc_time_str):
        try:
            utc_time = datetime.strptime(utc_time_str, '%Y-%m-%dT%H:%M:%SZ')
            kst_time = utc_time + timedelta(hours=9)
            return kst_time.strftime('%Y-%m-%d %H:%M:%S KST')
        except Exception as e:
            self.logger.error(f"Error converting time: {str(e)}")
            return utc_time_str

    def send_slack_message(self, message):
        try:
            req = Request(self.hook_url, data=json.dumps(message).encode('utf-8'))
            response = urlopen(req)
            response.read()
            self.logger.info("Message posted successfully")
        except HTTPError as e:
            self.logger.error("Request failed: %d %s", e.code, e.reason)
        except URLError as e:
            self.logger.error("Server connection failed: %s", e.reason)

    def create_base_slack_message(self, title, mention=""):
        return {
            "attachments": [{
                "blocks": []
            }],
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{mention}{title}"
                    }
                },
                {
                    "type": "divider"
                }
            ]
        }

    def add_fields_to_message(self, message, fields):
        message["attachments"][0]["blocks"].append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*{key}:*\n{value}"
                } for key, value in fields.items()
            ]
        })
        return message
EOF

  # Create symlink for Python to find the module
  ln -sf ../event_monitor_utils build/layers/event_monitor_utils/python/event_monitor_utils
  
  # Zip the layer
  (cd build/layers/event_monitor_utils && zip -r ../../event-monitor-utils-layer.zip python event_monitor_utils)
  
  echo -e "${GREEN}Lambda layer built successfully.${NC}"
}

# Function to build Lambda functions
build_functions() {
  echo "Building Lambda functions..."
  # IAM Event Handler
  mkdir -p build/functions/IAMEventHandler
  cat > build/functions/IAMEventHandler/lambda_function.py << 'EOF'
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
EOF

  # Console Login Event Handler
  mkdir -p build/functions/ConsoleLoginEventHandler
  cat > build/functions/ConsoleLoginEventHandler/lambda_function.py << 'EOF'
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
EOF

  # Secrets Manager Event Handler
  mkdir -p build/functions/SecretsManagerEventHandler
  cat > build/functions/SecretsManagerEventHandler/lambda_function.py << 'EOF'
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
EOF

  # EC2 Event Handler
  mkdir -p build/functions/EC2EventHandler
  cat > build/functions/EC2EventHandler/lambda_function.py << 'EOF'
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
EOF

  # RDS Event Handler
  mkdir -p build/functions/RDSEventHandler
  cat > build/functions/RDSEventHandler/lambda_function.py << 'EOF'
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
EOF

  # Zip the Lambda functions
  for func_dir in build/functions/*/; do
    func_name=$(basename "$func_dir")
    echo "Zipping $func_name..."
    (cd "$func_dir" && zip -r "../../$func_name.zip" .)
  done
  
  echo -e "${GREEN}Lambda functions built successfully.${NC}"
}

# Function to upload code to S3
upload_to_s3() {
  local region=$1
  local bucket_name="aws-cloudtrail-logs-259618073921-security"

  echo "Uploading code to S3 bucket: $bucket_name in $region..."

  # Check if bucket exists (비존재시에도 멈추지 않음)
  aws s3api head-bucket --bucket "$bucket_name" --region "$region" >/dev/null 2>&1 || {
    echo "Bucket $bucket_name not found. Creating..."

    aws s3api create-bucket \
      --bucket "$bucket_name" \
      --region "$region" \
      --create-bucket-configuration LocationConstraint="$region" \
      --acl private >/dev/null 2>&1 || true

    # Enable versioning (실패해도 무시)
    aws s3api put-bucket-versioning \
      --bucket "$bucket_name" \
      --versioning-configuration Status=Enabled \
      --region "$region" >/dev/null 2>&1 || true

    # Block public access
    aws s3api put-public-access-block \
      --bucket "$bucket_name" \
      --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
      --region "$region" >/dev/null 2>&1 || true
  }

  echo "Uploading Lambda layer..."
  aws s3 cp build/event-monitor-utils-layer.zip \
    "s3://$bucket_name/layers/event-monitor-utils-layer.zip" \
    --region "$region" --quiet || true

  echo "Uploading Lambda functions..."
  for func_zip in build/*.zip; do
    if [[ "$func_zip" != "build/event-monitor-utils-layer.zip" ]]; then
      func_name=$(basename "$func_zip" .zip)
      echo "Uploading $func_name..."
      aws s3 cp "$func_zip" "s3://$bucket_name/functions/$func_name.zip" \
        --region "$region" --quiet || true
    fi
  done

  echo -e "${GREEN}Upload to S3 completed successfully.${NC}"
  return 0
}

# Function to deploy the CloudFormation stack
deploy_stack() {
  local region=$1
  local is_primary=$2

  echo "Deploying CloudFormation stack in $region..."

  # 직접 값 입력
  local SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-https://hooks.slack.com/services/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}"
  local ALLOWED_IPS="192.168.1.1"

  local params=(
    "ParameterKey=SlackWebhookUrl,ParameterValue=${SLACK_WEBHOOK_URL}"
    "ParameterKey=AllowedIpAddresses,ParameterValue=${ALLOWED_IPS}"
    "ParameterKey=IsPrimaryRegion,ParameterValue=${is_primary}"
  )

  aws cloudformation deploy \
    --template-file aws-security-monitoring.yaml \
    --stack-name "$STACK_NAME" \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
      SlackWebhookUrl="${SLACK_WEBHOOK_URL}" \
      AllowedIpAddresses="${ALLOWED_IPS}" \
      IsPrimaryRegion="${is_primary}" \
    --region "$region" \
    --no-fail-on-empty-changeset

  if [ $? -eq 0 ]; then
    echo -e "${GREEN}CloudFormation stack deployed successfully in $region.${NC}"
  else
    echo -e "${RED}Failed to deploy CloudFormation stack in $region.${NC}"
    return 1
  fi

  return 0
}


# Main function
main() {
  check_prerequisites
  
  # Create build directories
  create_directories
  
  # Build the Lambda layer
  build_layer
  
  # Build the Lambda functions
  build_functions
  
  # Deploy to primary region first
  echo -e "${YELLOW}Deploying to primary region: $PRIMARY_REGION${NC}"
  upload_to_s3 "$PRIMARY_REGION"
  deploy_stack "$PRIMARY_REGION" "true"
  
  # Deploy to secondary regions
  for region in "${SECONDARY_REGIONS[@]}"; do
    echo -e "${YELLOW}Deploying to secondary region: $region${NC}"
    upload_to_s3 "$region"
    deploy_stack "$region" "false"
  done
  
  echo -e "${GREEN}Deployment completed successfully.${NC}"
}

# Execute main function
main "$@"
