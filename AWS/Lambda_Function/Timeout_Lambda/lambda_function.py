import boto3
import json
import os
import math

s3 = boto3.client("s3")

def lambda_handler(event, context):
    try:
        # 1️⃣ SQS 메시지 파싱
        record = event["Records"][0]
        body = json.loads(record["body"])
        bucket = body["bucket"]
        key = body["key"]  # e.g., Upload/sample.exe

        # 2️⃣ basename 추출 (sample.exe → sample)
        base_name = os.path.basename(key).replace(".exe", "")
        print(f"[*] Timeout ensemble started for {base_name}")

        # 4️⃣ Final_Report 존재 여부 확인
        final_key = f"AI_Result/Final_Report/{base_name}_ensemble_result.json"
        try:
            s3.head_object(Bucket=bucket, Key=final_key)
            print(f"[!] Final report already exists for {base_name}, skipping.")
            return {"statusCode": 200, "body": json.dumps({"msg": "Skipped (already exists)"})}
        except s3.exceptions.ClientError:
            pass

        # 5️⃣ AI_Result 폴더 내 결과 경로 설정
        result_paths = {
            "PE": f"AI_Result/PE/{base_name}_result.json",
            "Image": f"AI_Result/Image/{base_name}_result.json",
            "Opcode": f"AI_Result/Opcode/{base_name}_result.json"
        }

        results, existing = {}, {}
        for model, path in result_paths.items():
            try:
                obj = s3.get_object(Bucket=bucket, Key=path)
                results[model] = json.loads(obj["Body"].read().decode("utf-8"))
                existing[model] = True
            except Exception:
                existing[model] = False

        print(f"[+] Existing model results: {existing}")

        # -------------------------------
        # 6️⃣ 결과 조합 로직
        # -------------------------------
        for m in ["Opcode", "Image"]:
            if not existing.get(m):
                results[m] = {
                    "prediction": {
                        "label": "Indeterminate",
                        "reason": f"{m} analysis failed or result not found."
                    }
                }

        # PE는 반드시 존재해야 함
        if not existing.get("PE"):
            print("❌ PE result not found — cannot perform ensemble.")
            return {
                "statusCode": 200,
                "body": json.dumps({"msg": "No PE result found — skipping."})
            }

        # -------------------------------
        # 7️⃣ Evidence 기반 가중치 결합 (Optuna)
        # -------------------------------
        def logit(p):
            p = min(max(p, 1e-8), 1 - 1e-8)
            return math.log(p / (1 - p))

        def sigmoid(x):
            return 1 / (1 + math.exp(-x))

        # 모델 상태
        opc_label = results["Opcode"]["prediction"].get("label", "")
        img_exists = existing.get("Image", False)
        opc_exists = existing.get("Opcode", False)

        # 안전하게 확률 가져오기
        def safe_prob(model):
            try:
                return results[model]["prediction"].get("prob", 0.0)
            except:
                return 0.0

        p_pe = safe_prob("PE")
        p_img = safe_prob("Image") if img_exists else 0.0
        p_opc = safe_prob("Opcode") if opc_exists else 0.0

        # -------------------------------------------------
        # ✅ 조건 1: PE + IMG + OPC (3모델 정상)
        # -------------------------------------------------
        if opc_exists and img_exists and opc_label != "Indeterminate":
            weights = (0.41899811293701344, 0.201554043026697, 0.10120099800870452)
            k = 1.066
            bias_logit = 0.544
            threshold = 0.325
            probs = [p_pe, p_img, p_opc]
            logits = [logit(p) for p in probs]
            w_norm = [wi / sum(weights) for wi in weights]
            combined_logit = bias_logit + k * sum(wi * li for wi, li in zip(w_norm, logits))
            final_prob = sigmoid(combined_logit)
            models_used = ["PE", "Opcode", "Image"]

        # -------------------------------------------------
        # ✅ 조건 2: PE + IMG (Opcode 누락 or Indeterminate)
        # -------------------------------------------------
        elif img_exists and (not opc_exists or opc_label == "Indeterminate"):
            weights = (0.3749083677584684, 0.34577121790233634)
            k = 1.070
            bias_logit = 0.679
            threshold = 0.380
            probs = [p_pe, p_img]
            logits = [logit(p) for p in probs]
            w_norm = [wi / sum(weights) for wi in weights]
            combined_logit = bias_logit + k * sum(wi * li for wi, li in zip(w_norm, logits))
            final_prob = sigmoid(combined_logit)
            models_used = ["PE", "Image"]

        # -------------------------------------------------
        # ✅ 조건 3: PE + OPC (Image 누락)
        # -------------------------------------------------
        elif opc_exists and not img_exists:
            weights = (0.31276200066339077, 0.2635438633172833)
            k = 1.048
            bias_logit = 0.340
            threshold = 0.357
            probs = [p_pe, p_opc]
            logits = [logit(p) for p in probs]
            w_norm = [wi / sum(weights) for wi in weights]
            combined_logit = bias_logit + k * sum(wi * li for wi, li in zip(w_norm, logits))
            final_prob = sigmoid(combined_logit)
            models_used = ["PE", "Opcode"]

        # -------------------------------------------------
        # ✅ 조건 4: PE 단독 (나머지 실패)
        # -------------------------------------------------
        else:
            final_prob = p_pe
            threshold = 0.5
            models_used = ["PE"]

        # 🔹 최종 라벨 결정
        final_label = "malicious" if final_prob >= threshold else "benign"

        # -------------------------------
        # 9️⃣ 최종 JSON 생성
        # -------------------------------
        final_result = {
            "file": f"{base_name}_result",
            "ensemble_prediction": {
                "label": final_label,
                "final_prob": final_prob,
                "prob_percent": f"{final_prob*100:.2f}%",
                "models_used": models_used,
                "individual_probs": {
                    "PE": p_pe,
                    "Opcode": p_opc,
                    "Image": p_img
                },
                "individual_labels": {
                    "PE": results["PE"]["prediction"].get("label", "Unknown"),
                    "Opcode": results["Opcode"]["prediction"].get("label", "Unknown"),
                    "Image": results["Image"]["prediction"].get("label", "Unknown")
                }
            },
            "details": results
        }

        # -------------------------------
        # 🔟 최종 결과 업로드
        # -------------------------------
        s3.put_object(
            Bucket=bucket,
            Key=final_key,
            Body=json.dumps(final_result, ensure_ascii=False, indent=2)
        )
        print(f"[+] Final report uploaded → s3://{bucket}/{final_key}")

        return {
            "statusCode": 200,
            "body": json.dumps({"msg": "✅ Timeout ensemble completed", "file": final_key})
        }

    except Exception as e:
        print("❌ Error:", str(e))
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
