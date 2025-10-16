import math

def logit(p):
    """안정적인 logit 변환"""
    p = min(max(p, 1e-8), 1 - 1e-8)
    return math.log(p / (1 - p))

def sigmoid(x):
    """시그모이드 함수"""
    return 1 / (1 + math.exp(-x))

def predict_combined(*probs, mode=None):
    """
    - 3입력: predict_combined(pe_prob, img_prob, opc_prob)
    - 2입력: predict_combined(pe_prob, img_prob, mode='peimg')
             predict_combined(pe_prob, opc_prob, mode='peopc')
    출력: (확률%, 분류결과)
    """
    n = len(probs)
    if n not in (2, 3):
        raise ValueError("입력 확률 개수는 2개 또는 3개여야 합니다.")

    # -------------------
    # 3입력 (pe, img, opc)
    # -------------------
    if n == 3:
        w = (0.41899811293701344, 0.201554043026697, 0.10120099800870452)
        k = 1.066
        bias_logit = 0.544
        threshold = 0.325

    # -------------------
    # 2입력 (peimg / peopc)
    # -------------------
    elif n == 2:
        if mode == 'img':
            w = (0.3749083677584684, 0.34577121790233634)
            k = 1.070
            bias_logit = 0.679
            threshold = 0.380
        elif mode == 'opc':
            w = (0.31276200066339077, 0.2635438633172833)
            k = 1.070
            bias_logit = 0.679
            threshold = 0.380
        else:
            raise ValueError("2개 입력 시 mode 인자는 'peimg' 또는 'peopc' 여야 합니다.")

    # 가중치 정규화
    sw = sum(w)
    w_norm = [wi / sw for wi in w]

    # logit 변환 후 가중 평균
    logits = [logit(p) for p in probs]
    combined_logit = bias_logit + k * sum(wi * li for wi, li in zip(w_norm, logits))

    # 최종 확률
    prob = sigmoid(combined_logit)

    # 퍼센트 및 이진 분류
    percent = round(prob * 100, 2)
    label = "악성" if prob >= threshold else "정상"

    return percent, label


# -------------------
# 사용자 입력 실행부
# -------------------
if __name__ == "__main__":
    print("=== 🔍 확률 결합 예측기 ===")
    print("입력 예시:")
    print(" - 3입력: pe, img, opc 순서로 입력")
    print(" - 2입력: pe, img 또는 opc 입력 후 mode로 'peimg' 또는 'peopc' 선택\n")

    n = int(input("입력할 확률 개수 (2 또는 3): ").strip())

    if n == 3:
        pe = float(input("PE 확률 (0~1): ").strip())
        img = float(input("IMG 확률 (0~1): ").strip())
        opc = float(input("OPC 확률 (0~1): ").strip())
        percent, label = predict_combined(pe, img, opc)

    elif n == 2:
        pe = float(input("PE 확률 (0~1): ").strip())
        second = float(input("두 번째 확률 (IMG 또는 OPC) (0~1): ").strip())
        mode = input("mode 선택 ('img' 또는 'opc'): ").strip().lower()
        percent, label = predict_combined(pe, second, mode=mode)
    else:
        raise ValueError("입력 개수는 2 또는 3만 가능합니다.")

    print(f"\n예측 결과: {percent}% → {label}")
