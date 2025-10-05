# 파이프라인 로드 시 필요한 항수 정의
import numpy as np
def log_transform(X):
    return np.log1p(np.clip(X, a_min=0, a_max=None))
def remove_feature_prefixes(X):
    """모델이 학습된 이름과 일치시킵니다."""
    new_columns = [col.split('__')[-1] for col in X.columns]
    X.columns = new_columns
    return X