"""AWS IoT Policy generator"""

import json
from typing import Dict, Any

# pylint: disable=too-few-public-methods


class Policy:
    """thin-edge.io IoT Policy definitions"""

    template = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iot:Connect",
      "Resource": "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:client/${iot:Connection.Thing.ThingName}"
    },
    {
      "Effect": "Allow",
      "Action": "iot:Subscribe",
      "Resource": [
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topicfilter/thinedge/${iot:Connection.Thing.ThingName}/cmd/#",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topicfilter/$aws/things/${iot:Connection.Thing.ThingName}/shadow/#",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topicfilter/thinedge/devices/${iot:Connection.Thing.ThingName}/test-connection"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "iot:Receive",
      "Resource": [
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/thinedge/${iot:Connection.Thing.ThingName}/cmd",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/thinedge/${iot:Connection.Thing.ThingName}/cmd/*",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow/*",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/thinedge/devices/${iot:Connection.Thing.ThingName}/test-connection"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "iot:Publish",
      "Resource": [
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/thinedge/${iot:Connection.Thing.ThingName}/td",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/thinedge/${iot:Connection.Thing.ThingName}/td/*",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow/*",
        "arn:aws:iot:{{REGION}}:{{ACCOUNT_ID}}:topic/thinedge/devices/${iot:Connection.Thing.ThingName}/test-connection"
      ]
    }
  ]
}
"""

    def create(self, region="", account_id="") -> Dict[str, Any]:
        """Create an AWS policy definition for thin-edge.io"""
        policy = self.template
        policy = policy.replace(r"{{REGION}}", region)
        policy = policy.replace(r"{{ACCOUNT_ID}}", account_id)
        return json.loads(policy)
