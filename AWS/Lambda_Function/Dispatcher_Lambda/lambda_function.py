import json
import boto3

# SQS 클라이언트 생성
sqs = boto3.client("sqs")

# 분석용 SQS 큐 URL (ECS / 각 모델 분석용)
PE_QUEUE_URL = "/PE_Queue"
IMG_QUEUE_URL = "/Image_Queue"
OPCODE_QUEUE_URL = "/Opcode_Queue"

# 🆕 Timeout용 SQS 큐 (2분 후 앙상블 수행)
TIMEOUT_QUEUE_URL = "/Timeout"

QUEUE_URLS = [PE_QUEUE_URL, IMG_QUEUE_URL, OPCODE_QUEUE_URL]


def lambda_handler(event, context):
    # S3 이벤트 레코드 순회
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        # 공통 메시지 생성
        message = {
            "bucket": bucket,
            "key": key
        }

        # -------------------------------
        # 1️⃣ fan-out: 모든 분석 큐로 전송
        # -------------------------------
        for queue_url in QUEUE_URLS:
            sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps(message)
            )
            print(f"[DISPATCHER] Sent {key} -> {queue_url}")

        # -------------------------------
        # 2️⃣ Timeout 큐로도 메시지 전송 (2분 지연)
        # -------------------------------
        try:
            sqs.send_message(
                QueueUrl=TIMEOUT_QUEUE_URL,
                MessageBody=json.dumps({
                    "bucket": bucket,
                    "key": key,
                    "trigger": "timeout"
                }),
                DelaySeconds=120  # ⏰ 2분 후 Timeout Lambda 실행
            )
            print(f"[DISPATCHER] Scheduled timeout trigger for {key} (2 min delay)")

        except Exception as e:
            print(f"[!] Failed to send timeout message: {e}")

    return {
        "statusCode": 200,
        "body": json.dumps({"msg": "Fan-out messages + Timeout trigger sent"})
    }
