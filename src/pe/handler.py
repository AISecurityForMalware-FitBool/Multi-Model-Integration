import os, json, hashlib
import joblib
from pathlib import Path
from extract_features import extract_features_from_path
from transformers import log_transform, remove_feature_prefixes
import pandas as pd
import numpy as np 

# === 경로 설정 ===
BASE_DIR      = Path(__file__).resolve().parent.parent
PIPELINE_PATH = BASE_DIR / "artifacts" / "pipeline.pkl" 
YARA_PATH     = BASE_DIR / "rules" / "packer.yar"
PE_PATH       = Path("/home/alstn/SerialNumberDetectionTool.exe") // 샘플 PE 파일 경로


# --- 해시 함수 ---
def file_hashes(file_path: Path):
    h_md5 = hashlib.md5()
    h_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h_md5.update(chunk)
            h_sha256.update(chunk)
    return h_md5.hexdigest(), h_sha256.hexdigest()

# --- 메인 (로컬 테스트) ---
if __name__ == "__main__":
    # 파이프라인 로드
    pipeline = joblib.load(PIPELINE_PATH)

    # 1. 피처 추출
    X_one = extract_features_from_path(str(PE_PATH), yara_rules_path=str(YARA_PATH))
    
    # 2. 파이프라인에 원본 피처를 바로 전달
    prob = float(pipeline.predict_proba(X_one)[0, 1])
    label = int(prob >= 0.5)

    # 3. 전처리된 피처 추출 (결과 확인용)
    X_one_processed = pipeline.named_steps['preprocessor'].transform(X_one)
    X_one_processed = pipeline.named_steps['feature_cleaner'].transform(X_one_processed)
    
    # 4. 해시 계산
    md5, sha256 = file_hashes(PE_PATH)

    # 5. 결과 JSON
    result = {
        "file": str(PE_PATH),
        "hashes": {
            "md5": md5,
            "sha256": sha256,
        },
        "prediction": {
            "label": label,
            "prob": prob,
            "prob_percent": f"{prob*100:.2f}%",
        },
        "features_original": X_one.to_dict(orient="records")[0],
        "features_processed": X_one_processed.to_dict(orient="records")[0],
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


# === AWS Lambda 핸들러 ===
def lambda_handler(event, context):
    # 1. 파이프라인 로드 (모델 + 스케일러 포함)
    pipeline = joblib.load(PIPELINE_PATH)

    file_path = Path(event.get("file_path", PE_PATH))

    # 2. 피처 추출 
    X_one = extract_features_from_path(str(file_path), yara_rules_path=str(YARA_PATH))
    
    # 3. 파이프라인에 원본 피처를 전달
    prob  = float(pipeline.predict_proba(X_one)[0, 1])
    label = int(prob >= 0.5)
    
    # 4. 전처리된 피처 추출 (결과 확인용)
    X_one_processed = pipeline.named_steps['preprocessor'].transform(X_one)
    X_one_processed = pipeline.named_steps['feature_cleaner'].transform(X_one_processed)

    # 5. 해시 계산
    md5, sha256 = file_hashes(file_path)

    # 6. 결과 JSON 구성
    result = {
        "file": str(file_path),
        "hashes": {
            "md5": md5,
            "sha256": sha256,
        },
        "prediction": {
            "label": label,
            "prob": prob,
            "prob_percent": f"{prob*100:.2f}%",
        },
        "features_original": X_one.to_dict(orient="records")[0],
    }

    return {"statusCode": 200, "body": json.dumps(result, ensure_ascii=False)}