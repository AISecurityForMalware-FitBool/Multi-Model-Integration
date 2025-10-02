# Malware Detection with Multi-Model Integration (AWS Lambda)

## 프로젝트 개요
이 프로젝트는 **세 가지 AI 기반 악성코드 탐지 모델**과 **룰 기반 탐지 기법(YARA)**을 통합하여,  
AWS Lambda 환경에서 실행 가능한 악성코드 탐지 시스템을 구현한 결과물입니다.  

- **PE 기반 탐지 (XGBoost)** : PE 파일에서 39개 피처를 추출하여 분류
- **이미지 기반 탐지 (CNN)** : 실행 파일을 이미지로 변환 후 악성/정상 분류
- **Opcode 기반 탐지 (ML Classifier)** : 어셈블리 명령어 시퀀스를 기반으로 탐지
- **룰 기반 탐지 (YARA)** : 패커/압축 툴 사용 여부 판별

---

## 📂 프로젝트 구조
