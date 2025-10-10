#predict.py 

import joblib
import re
import sys
import json
import hashlib

# --- 1. 설정 및 함수 ---

OPCODE_WHITELIST = {
    'mov', 'lea', 'push', 'pop', 'pusha', 'popa', 'xchg', 'movzx', 'movsx', 'add', 
    'sub', 'inc', 'dec', 'mul', 'imul', 'div', 'idiv', 'neg', 'sbb', 'adc', 'and', 
    'or', 'xor', 'not', 'shl', 'shr', 'sar', 'rol', 'ror', 'jmp', 'call', 'retn', 
    'ret', 'leave', 'enter', 'je', 'jz', 'jne', 'jnz', 'jg', 'jnle', 'jge', 'jnl', 
    'jl', 'jnge', 'jle', 'jng', 'ja', 'jae', 'jb', 'jbe', 'jc', 'jnc', 'jo', 'jno', 
    'jp', 'jpe', 'jnp', 'jpo', 'js', 'jns', 'cmp', 'test', 'setz', 'setnz', 'seta', 
    'setae', 'setb', 'setbe', 'rep', 'repe', 'repne', 'movsb', 'movsd', 'stosb', 
    'stosd', 'cmpsb', 'scasb',
}


# 형식: 'push mov add' 처럼 Opcode 3개를 공백으로 연결한 문자열
TARGET_TRIGRAMS_TO_TRACK = [
    # --- 공통 피처 (20개) ---
    'mov mov cmp', 'mov lea mov', 'mov mov call', 'mov jmp mov', 
    'mov mov add', 'mov mov mov', 'test jz mov', 'mov mov lea', 
    'jz mov mov', 'mov mov test', 'mov call mov', 'cmp jnz mov', 
    'jmp mov mov', 'call mov mov', 'push push push', 'pop pop pop', 
    'mov test jz', 'lea mov call', 'lea call mov', 'lea mov mov',
    
    # --- 악성 특화 피처 (14개, "retn sub sub" 제외) ---
    'mov push call', 'mov imul mov', 'mov push mov', 'push call add', 
    'push push call', 'mov mov push', 'push push mov', 'imul mov mov', 
    'mov push push', 'mov mov imul', 'mov mul mov', 'push mov push', 
    'push mov call', 'push call mov','push mov mov',
    
    # --- 정상 특화 피처 (13개, "pop ret mov"와 "pop pop ret" 제외) ---
    'test jnz mov', 'mov cmp jz', 'mov call test', 'mov xor mov', 
    'jmp mov mov', 'call lea mov', 'push sub mov', 'pop ret mov', 
    'lea mov lea', 'sub mov mov', 'mov add pop', 'jnz mov mov', 
    'xor mov mov', 'call test jz', 'cmp jz mov'
]
def extract_opcodes_from_asm(filepath):
    """ .asm 파일에서 화이트리스트에 있는 Opcode만 추출 """
    opcode_pattern = re.compile(r'^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2,}\s+)*([a-zA-Z]{2,})')
    filtered_opcodes = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = opcode_pattern.search(line)
                if match:
                    opcode = match.group(1).lower()
                    if opcode in OPCODE_WHITELIST:
                        filtered_opcodes.append(opcode)
    except Exception:
        return []
    return filtered_opcodes

def get_file_hashes(filepath):
    """파일의 MD5, SHA256 해시를 계산"""
    BUF_SIZE = 65536
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data: break
                md5.update(data); sha256.update(data)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except FileNotFoundError:
        return {"md5": None, "sha256": None}

# --- 2. 메인 예측 함수 ---

def predict_asm_file(filepath):
    """하나의 .asm 파일을 입력받아 악성 여부를 JSON 형태로 출력"""
    result = {
        "file": filepath,
        "hashes": get_file_hashes(filepath),
        "prediction": {},
        "features": {}
    }

    try:
        model_pipeline = joblib.load('malware_detection_model.joblib')
        vectorizer = model_pipeline['vectorizer']   # TF-IDF 변환기
        model = model_pipeline['model']             # 머신러닝 모델
    except FileNotFoundError:
        result["error"] = "Model file 'malware_detection_model.joblib' not found."
        print(json.dumps(result, indent=2))
        return

    # 1. 파일에서 Opcode 리스트를 추출
    opcodes = extract_opcodes_from_asm(filepath)
    result["features"]["opcode_count"] = len(opcodes)

    # Opcode가 3개 미만이면 Trigram을 만들 수 없으므로 '판단 불가' 처리
    if len(opcodes) < 3:
        result["prediction"] = {"label": "Indeterminate", "reason": "Not enough opcodes."}
        print(json.dumps(result, indent=2))
        return

    # 2. Opcode 리스트를 3개씩 묶어 Trigram 리스트를 생성
    trigrams = [' '.join(opcodes[i:i+3]) for i in range(len(opcodes) - 2)]
    trigram_corpus = ' '.join(trigrams)
    result["features"]["trigram_count"] = len(trigrams)

    # 3. Trigram 문자열을 TF-IDF 벡터(숫자 벡터)로 변환
    tfidf_vector = vectorizer.transform([trigram_corpus])

    # 4. 사용자가 지정한 47개 핵심 Trigram의 TF-IDF 점수를 추출
    all_model_features = vectorizer.get_feature_names_out()
    feature_to_index_map = {feature: idx for idx, feature in enumerate(all_model_features)}
    target_trigram_scores = {}

    for trigram in TARGET_TRIGRAMS_TO_TRACK:
        if trigram in feature_to_index_map:
            index = feature_to_index_map[trigram]
            score = float(tfidf_vector[0, index]) # numpy.float32 -> python float 변환
            target_trigram_scores[trigram] = round(score, 6)
        else:
            target_trigram_scores[trigram] = 0.0
            
    result["features"]["target_trigrams"] = target_trigram_scores

    # 5. 모델이 인식한 유효한 단서(Trigram)의 개수를 계산
    evidence_count = tfidf_vector.nnz
    result["features"]["evidence_count"] = int(evidence_count)

    # 유효한 단서가 하나도 없으면 '판단 불가' 처리 (패킹/난독화 의심)
    if evidence_count == 0:
        result["prediction"] = {"label": "Indeterminate", "reason": "No known patterns found."}
        print(json.dumps(result, indent=2))
        return

     # 6. 모델을 사용하여 악성(1)인지 정상(0)인지 예측
    prediction = model.predict(tfidf_vector)
    prediction_proba = model.predict_proba(tfidf_vector)
    label = int(prediction[0])
    prob = float(prediction_proba[0][1]) # 악성일 확률

    # 7. 최종 예측 결과를 result 딕셔너리에 저장
    result["prediction"] = {
        "label": label,
        "prob": prob,
        "prob_percent": f"{prob:.2%}"
    }
    
    # 8. 모든 정보가 담긴 result 딕셔너리를 보기 좋은 JSON 형태로 출력
    print(json.dumps(result, indent=2, ensure_ascii=False))

# --- 3. 스크립트 실행 부분 ---
# 이 스크립트 파일이 직접 실행될 때만 아래 코드가 동작.
if __name__ == '__main__':
    # 터미널에서 준 인자가 2개가 아니면 (python, 파일경로) 사용법 출력
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python predict.py <path_to_asm_file>"}, indent=2))
    else:
        # 두 번째 인자(분석할 파일 경로)를 가져옴
        asm_file_path = sys.argv[1]
        # 메인 예측 함수를 호출
        predict_asm_file(asm_file_path)
