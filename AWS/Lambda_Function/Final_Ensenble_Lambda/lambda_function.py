import boto3
import os
import json
import math

s3 = boto3.client("s3")

def logit(p):
    p = min(max(p, 1e-8), 1 - 1e-8)
    return math.log(p / (1 - p))

def sigmoid(x):
    return 1 / (1 + math.exp(-x))

def lambda_handler(event, context):
    try:
        # 1. 이벤트에서 bucket, key 추출
        record = event["Records"][0]
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        # 2. basename 추출 (예: sample.json → sample)
        base_name = os.path.basename(key).replace(".json", "")

        # ==============================
        # 🔹 Final Report 존재 여부 확인
        # ==============================
        clean_name = base_name.replace("_result", "")
        final_key = f"AI_Result/Final_Report/{clean_name}_ensemble_result.json"

        try:
            s3.head_object(Bucket=bucket, Key=final_key)
            print(f"[!] Final report already exists for {clean_name}, skipping ensemble.")
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "msg": "⏭️ Final report already exists. Skipping execution.",
                    "key": final_key
                })
            }
        except s3.exceptions.ClientError:
            pass  # 존재하지 않으면 정상 진행

        # 3. AI_Result 내 3개 결과 파일 경로
        expected_files = {
            "PE": f"AI_Result/PE/{base_name}.json",
            "Image": f"AI_Result/Image/{base_name}.json",
            "Opcode": f"AI_Result/Opcode/{base_name}.json"
        }

        # 4. 존재 여부 확인
        existing = {}
        for k, path in expected_files.items():
            try:
                s3.head_object(Bucket=bucket, Key=path)
                existing[k] = True
            except:
                existing[k] = False

        # 5. 3개 다 있으면 → 읽어서 병합
        if all(existing.values()):
            results = {}
            for k, path in expected_files.items():
                obj = s3.get_object(Bucket=bucket, Key=path)
                content = obj["Body"].read().decode("utf-8")
                results[k] = json.loads(content)

##-----------------------------------------------------------------------------------위로 건들지 말것
            # features_processed 제거
            if "PE" in results and "features_processed" in results["PE"]:
                del results["PE"]["features_processed"]

            # ================================
            # 🔹 Evidence 기반 가중치 결합 (Optuna)
            # ================================
            opc_label = results["Opcode"]["prediction"].get("label", "")
            
            # 개별 확률값 안전하게 추출
            def safe_prob(model):
                try:
                    return results[model]["prediction"]["prob"]
                except:
                    return 0.0

            p_pe = safe_prob("PE")
            p_img = safe_prob("Image")
            p_opc = safe_prob("Opcode")

            # Opcode가 Indeterminate일 경우 → PE+IMG만 사용
            if opc_label == "Indeterminate":
                print("[!] Opcode result is Indeterminate — using only PE & Image models.")
                models_used = ["PE", "Image"]

                # Optuna 최적 조합 (pe+img)
                weights = (0.3749083677584684, 0.34577121790233634)
                k = 1.070
                bias_logit = 0.679
                threshold = 0.380

                probs = [p_pe, p_img]
                logits = [logit(p) for p in probs]
                sw = sum(weights)
                w_norm = [wi / sw for wi in weights]

                combined_logit = bias_logit + k * sum(wi * li for wi, li in zip(w_norm, logits))
                final_prob = sigmoid(combined_logit)

            else:
                models_used = ["PE", "Opcode", "Image"]

                # Optuna 최적 조합 (pe+img+opc)
                weights = (0.41899811293701344, 0.201554043026697, 0.10120099800870452)
                k = 1.066
                bias_logit = 0.544
                threshold = 0.325

                probs = [p_pe, p_img, p_opc]
                logits = [logit(p) for p in probs]
                sw = sum(weights)
                w_norm = [wi / sw for wi in weights]

                combined_logit = bias_logit + k * sum(wi * li for wi, li in zip(w_norm, logits))
                final_prob = sigmoid(combined_logit)

            final_label = "malicious" if final_prob >= threshold else "benign"

            # ==================================
            # 🔹 최종 결과 JSON 구성
            # ==================================
            final_result = {
                "file": clean_name + ".exe",
                "ensemble_prediction": {
                    "label": final_label,
                    "final_prob": final_prob,
                    "prob_percent": f"{final_prob*100:.2f}%",
                    "weights": {
                        "PE": weights[0],
                        "Opcode": weights[2] if len(weights) == 3 else 0.0,
                        "Image": weights[1]
                    },
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
                # Opcode가 Indeterminate라도 결과(details)에 반드시 포함
                "details": results
            }

#----------------------------------아래로 건들지 말것----------------------------------------------------------------
            s3.put_object(
                Bucket=bucket,
                Key=final_key,
                Body=json.dumps(final_result, ensure_ascii=False, indent=2)
            )

            print(f"[+] Final ensemble result generated for {clean_name}")
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "msg": "✅ Final ensemble result generated",
                    "key": final_key
                })
            }

        else:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "msg": "⌛ Waiting for other results",
                    "found": existing
                })
            }

    except Exception as e:
        print("❌ Error:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
