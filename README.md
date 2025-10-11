# Malware Detection with Multi-Model Integration
## 프로젝트 설명
이 프로젝트는 **세 가지 AI 기반 악성코드 탐지 모델**을 통합하여,  
**AWS Lambda 환경에서 실행 가능한 악성코드 탐지 시스템**을 구현한 결과물입니다.

- **PE 기반 탐지 (XGBoost)** : PE 파일에서 39개 피처를 추출하여 분류  
- **이미지 기반 탐지 (CNN)** : 실행 파일을 이미지로 변환 후 악성/정상 분류  
- **Opcode 기반 탐지 (XGBoost)** : 어셈블리 명령어 시퀀스를 기반으로 탐지  
- **SoftVoting** : Optuna 기반 파라미터 최적화 및 3가지 단일 모델의 가중합 결과 산출  

---

## 디렉토리 구조
```plaintext
Multi-Model Integration/
├── models/
│   ├── pe/
│   │   ├── pe_model.pkl 
│   │   └── features.txt 
│   ├── img/
│   │   └── img_model.keras
│   └── opcode/
│       ├── opc_model.joblib
│       └── features.txt 
│
├── src/
│   ├── softVoting/
│   │   └── softVoting.py
│   ├── pe/
│   │   ├── extract_fetures.py 
│   │   └── handler.py
│   ├── img/
│   │   └── img_src.py 
│   └── opcode/
│       └── opc_src.py
│
├── rules/
│   └── pe/
│       └── packer.yar
│
├── requirements/
│   ├── pe/
│   │   └── pe_requirements.txt
│   └── opc/
│       └── opc_requirements.txt
│
├── feature_list/
│   ├── pe/
│   │   └── pe_feature_list.txt
│   └── opc/
│       └── opc_feature_list.txt
│
├── README.md
└── .gitignore
````

---

## 1. Malware Detection - Static Analysis
- PE 파일 정적 분석 기반 악성코드 탐지 파이프라인입니다.
- PE 헤더, Import API, 문자열 통계, YARA 패커 탐지 피처를 추출하여 학습된 **XGBoost 모델**을 통해 악성/정상 여부를 분류합니다.

### 실행 환경 준비
```bash
# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 필요 라이브러리 설치
pip install -r requirements.txt
```

### 실행 방법
```bash
# handler.py 속 PE_PATH를 수정 후 실행
python src/handler.py
```

### 예측 결과 예시
```json
{
  "file": "/home/alstn/SerialNumberDetectionTool.exe",
  "hashes": {
    "md5": "72a03d0cd0bb0745704bbb02bb161187",
    "sha256": "e272684dbbd922d828968bbc7db79fe495fbc5cdad25f91bddb6a603558278fd"
  },
  "prediction": {
    "label": 1,
    "prob": 0.9463813900947571,
    "prob_percent": "94.64%"
  },
  "features_original": {
    "DllCharacteristics": 34112,
    "SizeOfStackReserve": 1048576,
    "AddressOfEntryPoint": 94062,
    "Characteristics": 258,
    ...
  }
}
```

---

## 2. Malware Detection - IMG Analysis
- **EfficientNetV2-S** 기반 이미지 분석 파이프라인입니다.
- PE 파일을 **GrayScale 이미지로 변환**하여 CNN 모델로 악성 여부를 판별합니다.

### 실행 환경 준비
```bash
pip install tensorflow opencv-python numpy
```

### 실행 방법
```bash
# handler.py 속 PE_PATH 수정 후 실행
python src/handler.py

# 또는 단일 실행
python inference_workflow.py
```

#### 입력 요청 예시
```
1. 분석할 PE 파일 경로를 입력하세요 (예: C:/malware/sample.exe)
2. 모델 파일 경로를 입력하세요 (예: ./PE_Inference_Assets/model/final_model_all_data.keras)
```

#### 결과 저장 위치
`./PE_Inference_Assets/inference_results/`

### 🧾 예측 결과 예시
```json
{
    "input_path": "/content/0b3731c524e6ba716f15087d85eae7e6225b6b51d4ae2fa6c142ff1523f57046.exe",
    "prediction": {
        "prob": 0.19639050960540771,
        "prob_percent": 19.63905143737793,
        "label": 0
    },
    "details": {
        "image_path": "./PE_Inference_Assets/inference_results/sample_exe_gray_300x300.png",
        "model_path": "/content/final_model_all_data.keras"
    }
}
```

### 출력 로그 예시
```bash
🚀 PE 파일 분석 시작: ./sample.exe
✅ 최종 모델 로드 중...
✅ PE 파일 전처리 (바이트 -> GrayScale 이미지 300x300) 중...
✅ 모델 예측 수행 중...

=============== 🔮 분석 결과 ===============
PE 파일명: sample.exe
예측 클래스: Normal
악성(Malware) 확률: 19.64%
정상(Normal) 확률: 80.36%
이미지 저장 경로: ./PE_Inference_Assets/inference_results/sample_exe_gray_300x300.png
==========================================

✅ JSON 결과 저장 완료: ./PE_Inference_Assets/inference_results/sample_exe_image_result.json
```

---

## 3. Malware Detection - Opcode Analysis

### 실행 환경 준비
```bash
# 1. 저장소 복제
git clone https://github.com/poatan2/opcode-classifier.git
cd opcode-classifier

# 2. (선택) 가상 환경 생성 및 활성화
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows

# 3. 필요 라이브러리 설치
pip install -r requirements.txt
```

### 예측 스크립트 실행
`model/` 폴더에 저장된 모델을 사용하여 새로운 ASM 파일을 분석합니다.

```bash
python src/predict.py "path/to/your/sample.asm"
```

### 예측 결과 예시

#### 1) 판단 가능한 경우
```json
{
  "file": "C:\\Users\\sample\\MLEngineStub.asm",
  "hashes": {
    "md5": "69d0f5fe632c16a052ded95716321cf2",
    "sha256": "c13f669a2ac0d7450ba721d1856dbcdbe50e5107068a7d65a7a8598392bd5d50"
  },
  "prediction": {
    "label": 0,
    "prob": 0.007786966860294342,
    "prob_percent": "0.78%"
  },
  "features": {
    "opcode_count": 9264,
    "trigram_count": 9262,
    "target_trigrams": {
      "mov mov cmp": 0.00993,
      "mov lea mov": 0.199031,
      "mov mov call": 0.055323,
      ...
    },
    "evidence_count": 42
  }
}
```

#### 2) 판단 불가능한 경우
```json
{
  "file": "C:\\Users\\sample\\Ld2yXjPFsUhkZGmb3lcp.asm",
  "hashes": {
    "md5": "58d46cafebb97d67a54717c787bf05c6",
    "sha256": "2c17b8868de139307bff2067e3e1287bff11521e4af8d296dc25f8ef65ff06dc"
  },
  "prediction": {
    "label": "Indeterminate",
    "reason": "Not enough opcodes."
  },
  "features": {
    "opcode_count": 0
  }
}
```

---

## 4. SoftVoting (앙상블)
- 3가지 단일 모델(PE, IMG, OPCODE)의 예측 결과를 Optuna로 최적화된 가중치를 사용하여 **Soft Voting** 방식으로 최종 판단합니다.

---

## * 참고 사항
* KISIA의 AI보안 악성코드반 fit bool의 프로젝트입니다.
* 각 모델별 Feature List와 Requirements는 `feature_list/`, `requirements/` 폴더 내 존재합니다.
* 예시 결과는 테스트용으로 생성된 샘플이며, 실제 환경에서는 로그 저장 및 S3 업로드와 연동 가능합니다.

