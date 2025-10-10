# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Dict, Optional
import os, re, math
from pathlib import Path

import pandas as pd

# 선택 모듈: 없으면 일부 기능만 비활성화
try:
    import pefile
except Exception:
    pefile = None
try:
    import lief
except Exception:
    lief = None
try:
    import yara
except Exception:
    yara = None

# ===== 경로 & 컬럼 순서 로드 =====
BASE_DIR = Path(__file__).resolve().parent.parent   # static/
FEATURE_LIST_PATH = BASE_DIR / "artifacts" / "feature_list.txt"
RULE_DEFAULT_PATH = BASE_DIR / "rules" / "packer.yar"

def _load_feature_order() -> list[str]:
    if not FEATURE_LIST_PATH.exists():
        raise FileNotFoundError(f"feature_list.txt not found: {FEATURE_LIST_PATH}")
    cols = [ln.strip() for ln in FEATURE_LIST_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(cols) == 0:
        raise ValueError("feature_list.txt is empty")
    return cols

FEATURE_COLUMNS = _load_feature_order()
DEFAULTS = {c: 0.0 for c in FEATURE_COLUMNS}

# ===== YARA (옵션) =====
_YARA_RULES = None
def _compile_yara(path: str | Path):
    if yara is None:
        return None
    path = str(path)
    if not (os.path.isfile(path) and path.lower().endswith((".yar", ".yara"))):
        return None
    try:
        return yara.compile(filepaths={"ns0": os.path.abspath(path)})
    except Exception:
        return None

def _get_yara_rules(path: Optional[str | Path]) -> Optional["yara.Rules"]:
    global _YARA_RULES
    if _YARA_RULES is None:
        _YARA_RULES = _compile_yara(path or RULE_DEFAULT_PATH)
    return _YARA_RULES

def _scan_packer_yara(raw: bytes, rules) -> Dict[str, int]:
    out = {
        "yara_has_packer_generic": 0, "yara_count_packer": 0,
        "yara_has_upx_like": 0, "yara_has_mpress_like": 0, "yara_has_aspack_like": 0,
    }
    if rules is None or yara is None:
        return out
    try:
        matches = rules.match(data=raw, timeout=10)
        if not matches:
            return out
        uniq = {(m.namespace, m.rule) for m in matches}
        out["yara_count_packer"] = len(uniq)
        if out["yara_count_packer"] > 0:
            out["yara_has_packer_generic"] = 1
        tokens = []
        names = []
        for m in matches:
            names.append(m.rule)
            tokens.append(m.rule.lower())
            tokens.extend([t.lower() for t in m.tags])
        s = " ".join(tokens)
        out["yara_has_upx_like"]    = 1 if "upx" in s else 0
        out["yara_has_aspack_like"] = 1 if "aspack" in s else 0
        mpress_re = re.compile(r'(?<![A-Za-z0-9])mpress(?![A-Za-z0-9])', re.I)
        out["yara_has_mpress_like"] = 1 if ("mpress" in s) or any(mpress_re.search(n) for n in names) else 0
    except Exception:
        pass
    return out

# ===== 유틸 =====
def _entropy(data: bytes | str) -> float:
    if data is None:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    n = len(data)
    if n == 0:
        return 0.0
    from collections import Counter
    cnts = Counter(data)
    ent = 0.0
    inv_log2 = 1.0 / math.log(2.0)
    for v in cnts.values():
        p = v / n
        ent -= p * (math.log(p) * inv_log2)
    return float(ent)

def _ensure_schema(row: Dict[str, float]) -> pd.DataFrame:
    """누락 0 채움 + 초과 무시 + 순서 고정 + 숫자 캐스팅."""
    cleaned = {k: row.get(k, DEFAULTS[k]) for k in FEATURE_COLUMNS}
    df = pd.DataFrame([cleaned], columns=FEATURE_COLUMNS)
    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df.fillna(0.0)

# ===== 피처 추출 핵심 =====
def extract_features_from_bytes(file_bytes: bytes, yara_rules_path: Optional[str | Path] = None) -> pd.DataFrame:
    feats: Dict[str, float] = {}

    # 1) PE 헤더 (pefile)
    if pefile is not None:
        pe = None
        try:
            pe = pefile.PE(data=file_bytes, fast_load=True)
            DOS  = getattr(pe, "DOS_HEADER", None)
            FILE = getattr(pe, "FILE_HEADER", None)
            OPT  = getattr(pe, "OPTIONAL_HEADER", None)
            g = lambda obj, attr, d=-1: getattr(obj, attr, d) if obj else d
            feats.update({
                "DllCharacteristics": g(OPT,  "DllCharacteristics"),
                "MajorImageVersion": g(OPT,  "MajorImageVersion"),
                "MajorOperatingSystemVersion": g(OPT, "MajorOperatingSystemVersion"),
                "SizeOfStackReserve": g(OPT, "SizeOfStackReserve"),
                "AddressOfEntryPoint": g(OPT, "AddressOfEntryPoint"),
                "Characteristics": g(FILE, "Characteristics"),
                "SizeOfHeaders": g(OPT, "SizeOfHeaders"),
                "SizeOfInitializedData": g(OPT, "SizeOfInitializedData"),
                "SizeOfUninitializedData": g(OPT, "SizeOfUninitializedData"),
                "MinorSubsystemVersion": g(OPT, "MinorSubsystemVersion"),
                "ImageBase": g(OPT, "ImageBase"),
                "MajorLinkerVersion": g(OPT, "MajorLinkerVersion"),
                "NumberOfSections": g(FILE, "NumberOfSections"),
                "MinorImageVersion": g(OPT, "MinorImageVersion"),
                "SizeOfStackCommit": g(OPT, "SizeOfStackCommit"),
                "e_lfanew": g(DOS, "e_lfanew"),
                "e_minalloc": g(DOS, "e_minalloc"),
                "e_ovno": g(DOS, "e_ovno"),
                "Machine": g(FILE, "Machine"),
                "PointerToSymbolTable": g(FILE, "PointerToSymbolTable"),
                "NumberOfSymbols": g(FILE, "NumberOfSymbols"),
                "SizeOfCode": g(OPT, "SizeOfCode"),
                "BaseOfCode": g(OPT, "BaseOfCode"),
                "SectionAlignment": g(OPT, "SectionAlignment"),
                "FileAlignment": g(OPT, "FileAlignment"),
            })
        except Exception:
            # 파싱 실패 시 기본값
            for k in [
                "DllCharacteristics","MajorImageVersion","MajorOperatingSystemVersion",
                "SizeOfStackReserve","AddressOfEntryPoint","Characteristics",
                "SizeOfHeaders","SizeOfInitializedData","SizeOfUninitializedData",
                "MinorSubsystemVersion","ImageBase","MajorLinkerVersion",
                "NumberOfSections","MinorImageVersion","SizeOfStackCommit",
                "e_lfanew","e_minalloc","e_ovno","Machine","PointerToSymbolTable","NumberOfSymbols",
                "SizeOfCode","BaseOfCode","SectionAlignment","FileAlignment",
            ]:
                feats[k] = -1
        finally:
            if pe:
                try: pe.close()
                except Exception: pass
    else:
        # pefile 미설치 시 최소 값
        for k in [
            "DllCharacteristics","MajorImageVersion","MajorOperatingSystemVersion",
            "SizeOfStackReserve","AddressOfEntryPoint","Characteristics",
            "SizeOfHeaders","SizeOfInitializedData","SizeOfUninitializedData",
            "MinorSubsystemVersion","ImageBase","MajorLinkerVersion",
            "NumberOfSections","MinorImageVersion","SizeOfStackCommit",
            "e_lfanew","e_minalloc","e_ovno","Machine","PointerToSymbolTable","NumberOfSymbols",
            "SizeOfCode","BaseOfCode","SectionAlignment","FileAlignment",
        ]:
            feats[k] = -1

    # 2) 임포트 (lief 우선, 실패 시 pefile)
    all_imports, dlls, imports_per_dll = [], set(), []
    used_lief = False
    if lief is not None:
        try:
            lb = lief.PE.parse(list(file_bytes))
            if lb and getattr(lb, "imports", None):
                used_lief = True
                for entry in lb.imports:
                    if not entry.name: continue
                    dlls.add(entry.name.lower())
                    cnt = 0
                    for imp in entry.entries:
                        if imp.name:
                            all_imports.append(imp.name); cnt += 1
                        elif getattr(imp, "is_ordinal", False):
                            all_imports.append(f"Ordinal_{imp.ordinal}"); cnt += 1
                    if cnt > 0: imports_per_dll.append(cnt)
        except Exception:
            used_lief = False

    if not used_lief and pefile is not None:
        try:
            pe2 = pefile.PE(data=file_bytes, fast_load=True)
            if hasattr(pe2, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe2.DIRECTORY_ENTRY_IMPORT:
                    name = (entry.dll or b"").decode("utf-8", "ignore").lower()
                    if name: dlls.add(name)
                    cnt = 0
                    for imp in entry.imports:
                        if imp.name:
                            all_imports.append(imp.name.decode("utf-8", "ignore")); cnt += 1
                    if cnt > 0: imports_per_dll.append(cnt)
            try: pe2.close()
            except Exception: pass
        except Exception:
            pass

    feats["imports_total"] = len(all_imports)
    feats["imports_unique"] = len(set(all_imports))
    feats["import_dlls_unique"] = len(dlls)
    feats["imports_max_per_dll"] = max(imports_per_dll) if imports_per_dll else 0
    feats["imports_entropy"] = _entropy(''.join(all_imports)) if all_imports else 0.0

    # 3) 문자열 통계
    strings = re.findall(rb"[\x20-\x7e]{4,}", file_bytes)
    if strings:
        printable_len = sum(len(s) for s in strings)
        feats["strings_entropy"] = _entropy(b"".join(strings))
        feats["strings_printable_ratio"] = (printable_len / len(file_bytes)) if file_bytes else 0.0
        feats["strings_avg_len"] = (printable_len / len(strings)) if strings else 0.0
    else:
        feats["strings_entropy"] = 0.0
        feats["strings_printable_ratio"] = 0.0
        feats["strings_avg_len"] = 0.0
    feats["strings_base64_blob_count"] = len(re.findall(rb'[A-Za-z0-9+/=]{20,}', file_bytes))

    # 4) YARA 패커
    try:
        rules = _get_yara_rules(yara_rules_path)
        feats.update(_scan_packer_yara(file_bytes, rules))
    except Exception:
        feats.update({
            "yara_has_packer_generic": 0,
            "yara_count_packer": 0,
            "yara_has_upx_like": 0,
            "yara_has_mpress_like": 0,
            "yara_has_aspack_like": 0,
        })

    return _ensure_schema(feats)

def extract_features_from_path(file_path: str | Path, yara_rules_path: Optional[str | Path] = None) -> pd.DataFrame:
    file_path = str(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    # 명시한 yara path가 들어오면 재컴파일
    if yara_rules_path is not None:
        global _YARA_RULES
        _YARA_RULES = _compile_yara(yara_rules_path)
    return extract_features_from_bytes(data, yara_rules_path)

def df_to_dict(df: pd.DataFrame) -> Dict[str, float]:
    assert df.shape[0] == 1, "df must be a single-row DataFrame"
    return {c: float(df.iloc[0][c]) for c in df.columns}
