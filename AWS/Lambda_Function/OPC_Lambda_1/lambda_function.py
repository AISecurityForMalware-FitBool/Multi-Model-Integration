import json
import boto3
import os

ecs = boto3.client("ecs")

# ECS 클러스터와 태스크 정의
CLUSTER_ARN = ""
TASK_DEF_ARN = "a"
SUBNET_ID = ""     
SECURITY_GROUP_ID = ""  

def lambda_handler(event, context):
    try:
        print("[*] Received SQS event")
        print(json.dumps(event, indent=2))

        # SQS 이벤트 → 메시지 파싱
        for record in event["Records"]:
            body = json.loads(record["body"])
            bucket = body["bucket"]
            key = body["key"]

            print(f"[*] Launching ECS task for {key}")

            # ECS RunTask 호출
            response = ecs.run_task(
                cluster=CLUSTER_ARN,
                taskDefinition=TASK_DEF_ARN,
                launchType="FARGATE",
                count=1,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [SUBNET_ID],
                        "securityGroups": [SECURITY_GROUP_ID],
                        "assignPublicIp": "ENABLED"
                    }
                },
                overrides={
                    "containerOverrides": [
                        {
                            "name": "ghidra-container",  # ✅ Task Definition 안의 컨테이너 이름과 동일해야 함
                            "command": [
                                 bucket, key
                            ]
                        }
                    ]
                }
            )

            print(f"[+] ECS task started: {response['tasks'][0]['taskArn']}")

        return {
            "statusCode": 200,
            "body": json.dumps({"message": "ECS task(s) launched successfully"})
        }

    except Exception as e:
        print(f"[!] Error: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
