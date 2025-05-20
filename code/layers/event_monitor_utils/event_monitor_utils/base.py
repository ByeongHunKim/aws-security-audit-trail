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
