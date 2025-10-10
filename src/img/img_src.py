# -*- coding: utf-8 -*-
#
# PE 파일 단일 추론 (Inference) 워크플로우 (Colab/로컬 호환)
# - PE 파일과 모델 파일을 각각 Colab 업로드 또는 로컬 콘솔 입력을 통해 지정합니다.

import os
import math
import numpy as np
import tensorflow as tf
import cv2
import json # 💡 JSON 처리를 위해 추가
from pathlib import Path
from typing import Dict, Any

# --- Colab 파일 업로드 모듈 임포트 시도 ---
try:
    from google.colab import files
    IS_COLAB = True
except ImportError:
    files = None
    IS_COLAB = False
# ----------------------------------------

# =========================================================================
# 🚨 사용자 지정 필수 경로 설정 (기본값 설정 및 폴더 생성)
# =========================================================================

# 1. 로컬 작업 공간 설정 (스크립트 실행 위치 기준)
LOCAL_ASSET_ROOT = "./PE_Inference_Assets"
os.makedirs(LOCAL_ASSET_ROOT, exist_ok=True)

# 2. 모델 폴더 경로 및 기본 모델 파일 이름 (업로드 후 저장될 임시 폴더)
MODEL_DIR = os.path.join(LOCAL_ASSET_ROOT, "model")
os.makedirs(MODEL_DIR, exist_ok=True)

# 3. 분석된 이미지 및 결과 저장 경로
# 💡 경로를 ./src로 직접 수정
INFERENCE_IMG_SAVE_DIR = "./src"
os.makedirs(INFERENCE_IMG_SAVE_DIR, exist_ok=True)
 
# 💡 JSON 결과 저장 경로도 ./src로 직접 수정
INFERENCE_JSON_SAVE_DIR = "./src" # 이미지와 같은 폴더에 저장
os.makedirs(INFERENCE_JSON_SAVE_DIR, exist_ok=True)

# =========================================================================
# 하이퍼파라미터 및 유틸리티 (원본 코드와 동일)
# =========================================================================

IMG_SIZE = 300
CLASS_NAMES = ["Normal", "Malware"] # 0: Normal, 1: Malware
from tensorflow.keras.applications import efficientnet_v2
preprocess_input = efficientnet_v2.preprocess_input

# [원본 전처리 코드에서 가져온 함수: 1. width_by_size]
def width_by_size(n_bytes: int) -> int:
    """바이트 크기에 따라 이미지의 너비를 결정합니다."""
    if n_bytes < 10*1024: return 32
    if n_bytes < 30*1024: return 64
    if n_bytes < 60*1024: return 128
    if n_bytes < 100*1024: return 256
    if n_bytes < 200*1024: return 384
    if n_bytes < 500*1024: return 512
    if n_bytes < 1024*1024: return 768
    return 1024

# [원본 전처리 코드에서 가져온 함수: 2. exe_bytes_to_gray_square]
def exe_bytes_to_gray_square(bytes_data: bytes, target=IMG_SIZE):
    """PE 바이트 데이터를 GrayScale 정사각형 이미지 (300x300)로 변환합니다."""
    N = len(bytes_data)
    W = width_by_size(N)
    H = math.ceil(N / W)
    arr = np.frombuffer(bytes_data, dtype=np.uint8)

    # 0으로 패딩 (H*W 크기로 맞춤)
    if len(arr) < H*W:
        arr = np.pad(arr, (0, H*W - len(arr)), constant_values=0)

    img = arr.reshape(H, W)

    # 정사각형으로 확장 후 리사이즈 (cv2.INTER_AREA 사용)
    side = max(H, W)
    sq = np.zeros((side, side), dtype=np.uint8)
    sq[:H, :W] = img
    sq = cv2.resize(sq, (target, target), interpolation=cv2.INTER_AREA)
    return sq

# =========================================================================
# 메인 추론 함수 (JSON 저장 로직 및 형식 통일)
# =========================================================================

def inference_pipeline(pe_path: str, model_path: str) -> Dict[str, Any]:
    """사용자 입력 경로를 받아 모델 로드 및 PE 파일 분석을 수행합니다."""
    print(f"🚀 PE 파일 분석 시작: {pe_path}")

    if not os.path.exists(pe_path):
        print(f"[ERROR] PE 파일을 찾을 수 없습니다: {pe_path}")
        return {"error": "PE file not found"}

    # 1. 최고 성능 모델 로드
    if not os.path.exists(model_path):
        print(f"[ERROR] 학습된 최종 모델을 찾을 수 없습니다: {model_path}")
        return {"error": "Model file not found"}

    print("✅ 최종 모델 로드 중...")
    try:
        model = tf.keras.models.load_model(model_path)
    except Exception as e:
        print(f"[ERROR] 모델 로드 실패: {e}")
        return {"error": str(e)}

    # 2. PE 파일 전처리 및 이미지화
    print("✅ PE 파일 전처리 (바이트 -> GrayScale 이미지 300x300) 중...")
    try:
        with open(pe_path, "rb") as f:
            data_bytes = f.read()

        # 2-1. GrayScale 이미지 변환 (원본 전처리 로직)
        gray_img_np = exe_bytes_to_gray_square(data_bytes, target=IMG_SIZE)

        # 2-2. 3채널(RGB)로 확장
        input_image_raw = np.stack([gray_img_np]*3, axis=-1).astype(np.float32)

        # 2-3. EfficientNetV2 표준 전처리 적용
        input_image_processed = preprocess_input(input_image_raw)

        # 2-4. 배치 차원 추가
        input_tensor = np.expand_dims(input_image_processed, axis=0)

    except Exception as e:
        print(f"[ERROR] 전처리 실패: {e}")
        return {"error": str(e)}

    # 3. 예측 수행
    print("✅ 모델 예측 수행 중...")
    prediction_proba = model.predict(input_tensor, verbose=0)[0][0]

    # 4. 결과 판별 및 확률 계산
    threshold = 0.5
    predicted_class = 1 if prediction_proba >= threshold else 0

    malware_prob_percent = prediction_proba * 100
    normal_prob_percent = (1.0 - prediction_proba) * 100

    file_name = Path(pe_path).stem + "_" + Path(pe_path).suffix.replace(".", "")

    # 5. 이미지 저장 (GrayScale PNG)
    output_img_path = os.path.join(INFERENCE_IMG_SAVE_DIR, f"{file_name}_gray_{IMG_SIZE}x{IMG_SIZE}.png")

    try:
        cv2.imwrite(output_img_path, gray_img_np)
        print(f"✅ 이미지 저장 완료: {output_img_path}")
    except Exception as e:
        print(f"[ERROR] 이미지 저장 실패: {e}")

    # 6. 최종 결과 딕셔너리 구성 (💡 Prediction 블록을 PE Feature 모델 형식에 맞게 수정)
    result_dict = {
        "input_path": pe_path,
        "prediction": {
            "prob": float(prediction_proba),             # 악성(Malware) 확률 (0~1)
            "prob_percent": float(malware_prob_percent), # 악성(Malware) 확률 (퍼센트)
            "label": predicted_class                     # 예측 인덱스 (0: Normal, 1: Malware)
        },
        "details": {
            # PE Feature 모델에는 없는 정보이지만, 이미지 모델에만 유효한 상세 정보는 details에 유지
            "image_path": output_img_path,
            "model_path": model_path
        }
    }

    # 7. 최종 결과 출력 (악성/정상 판별 및 확률) - 출력 메시지는 가독성을 위해 유지
    print(f"\n{'='*15} 🔮 분석 결과 {'='*15}")
    print(f"PE 파일명: {Path(pe_path).name}")
    print(f"예측 클래스: {CLASS_NAMES[predicted_class]}")
    print(f"악성(Malware) 확률: **{malware_prob_percent:.2f}%**")
    print(f"정상(Normal) 확률: **{normal_prob_percent:.2f}%**")
    print(f"이미지 저장 경로: {output_img_path}")
    print(f"{'='*36}\n")

    # 8. 💡 JSON 파일 저장 (추가된 핵심 기능)
    json_filename = f"{file_name}_image_result.json"
    output_json_path = os.path.join(INFERENCE_JSON_SAVE_DIR, json_filename)

    try:
        with open(output_json_path, 'w', encoding='utf-8') as f:
            # indent=4를 사용하여 JSON을 보기 좋게 저장합니다.
            json.dump(result_dict, f, ensure_ascii=False, indent=4)
        print(f"✅ JSON 결과 저장 완료: {output_json_path}")
        result_dict['json_path'] = output_json_path
    except Exception as e:
        print(f"[ERROR] JSON 저장 실패: {e}")

    return result_dict


def get_user_input_paths():
    """환경에 따라 PE 파일과 모델 파일 경로를 입력받는 함수."""
    print("="*50)
    print(" PE 파일 및 모델 경로 지정")
    print("="*50)

    pe_path = ""
    model_path = ""

    # 1. PE 파일 경로 입력
    if IS_COLAB:
        print("1. 분석할 PE 파일을 업로드하세요 (Colab 'Choose Files' 버튼 사용):")
        uploaded = files.upload()
        if uploaded:
            pe_path = os.path.join("/content", list(uploaded.keys())[0])
        else:
            print("[WARN] PE 파일 업로드 취소.")
            return "", ""
    else:
        pe_path = input("1. 분석할 PE 파일 경로를 입력하세요 (예: C:/malware/sample.exe): ").strip()

    # 2. 모델 파일 경로 입력
    print("\n2. 사용할 모델 파일(final_model_all_data.keras) 경로를 지정합니다.")

    if IS_COLAB:
        print("모델 파일을 업로드하세요. (Colab 'Choose Files' 버튼 사용):")
        uploaded_model = files.upload()
        if uploaded_model:
            model_path = os.path.join("/content", list(uploaded_model.keys())[0])
        else:
            print("[WARN] 모델 파일 업로드 취소.")
            return pe_path, ""
    else:
        model_path = input("모델 파일 경로를 입력하세요 (예: ./PE_Inference_Assets/model/final.keras): ").strip()

    print(f"\n-> PE 파일 경로: {pe_path}")
    print(f"-> 모델 파일 경로: {model_path}")

    return pe_path, model_path


if __name__ == "__main__":

    # 사용자로부터 PE 파일 경로 및 모델 파일 경로를 입력받음
    user_pe_path, final_model_path = get_user_input_paths()

    # 유효성 검사 및 분석 실행
    if user_pe_path and final_model_path:
        # 💡 추론 결과를 받아서 (선택 사항) 추가 처리가 가능합니다.
        result = inference_pipeline(user_pe_path, final_model_path)

        # 💡 JSON 파일 저장 확인 메시지
        if "json_path" in result:
            print(f"\n📢 보팅 스크립트가 사용할 이미지 모델 결과: {result['json_path']}")

    else:
        print("[ERROR] 유효한 PE 파일 경로와 모델 파일 경로가 모두 지정되지 않아 분석을 종료합니다.")