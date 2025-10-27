import json
import subprocess

def lambda_handler(event, context):
    print("[*] Event Received:", event)

    try:
        record = event["Records"][0]
        body = json.loads(record["body"])  # SQS body → dict
        bucket = body["bucket"]
        key = body["key"]
    except Exception as e:
        print("[ERROR] bucket/key not found in SQS message:", e)
        return {"statusCode": 400, "body": "Invalid event format"}

    # run_one.sh 실행
    try:
        result = subprocess.run(
            ["/opt/run_one.sh", bucket, key],
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout)
        return {"statusCode": 200, "body": "ASM Export Success"}
    except subprocess.CalledProcessError as e:
        print("[ERROR] run_one.sh failed:", e.stderr)
        return {"statusCode": 500, "body": "ASM Export Failed"}
