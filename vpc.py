import boto3
import json
import os

sns = boto3.client("sns")
THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", 5))
TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

def lambda_handler(event, context):
    alerts = []
    for record in event.get("records", []):
        data = json.loads(record.get("data", "{}"))
        src = data.get("srcaddr")
        dst = data.get("dstaddr")
        action = data.get("action")
        
        if action == "REJECT" or data.get("bytes", 0) > THRESHOLD:
            alerts.append(f"Suspicious traffic detected: {src} → {dst}")

    if alerts and TOPIC_ARN:
        message = "\n".join(alerts)
        sns.publish(TopicArn=TOPIC_ARN, Message=message)

    return {"status": "processed", "alerts_triggered": len(alerts)}
