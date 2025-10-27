import os
import json
import boto3

s3 = boto3.client("s3")
bedrock = boto3.client("bedrock-runtime", region_name="ap-northeast-2")

def lambda_handler(event, context):
    try:
        # 1️⃣ S3 이벤트 정보
        record = event["Records"][0]
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        print(f"📥 Triggered by: s3://{bucket}/{key}")

        # 2️⃣ S3에서 JSON 파일 다운로드
        local_path = f"/tmp/{os.path.basename(key)}"
        s3.download_file(bucket, key, local_path)
        with open(local_path, "r", encoding="utf-8") as f:
            final_report = json.load(f)

        # 3️⃣ 모델 결과에서 주요 값 추출
        final_prob = final_report["ensemble_prediction"]["final_prob"]
        score_malicious = int(final_prob * 100)
        score_benign = 100 - score_malicious
        label = final_report["ensemble_prediction"]["label"]

        # 4️⃣ 프롬프트 정의
        prompt = f"""
        당신은 전문 보안 분석가입니다. 아래 JSON은 동일 파일에 대해 3개 모델(PE 정적 피처, Opcode, 바이너리 이미지) 결과와 
        소프트 보팅(가중치 합산) 최종 결과를 담고 있습니다. 
        이 JSON만을 근거로, **모델 결과의 근거와 불확실성**을 명확히 설명하는 xAI 스타일의 요약 리포트를 작성하세요.

        # 작성 원칙
        - 과도한 확정 표현 금지: "가능성이 있다/의심된다/정황상" 표현을 사용.
        - 허위 정보/추정 금지: JSON에 없는 사실을 지어내지 말고, 과해석하지 말 것.
        - 수치 표기: 확률은 소수 2자리까지 %로 표기.
        - 일관된 Markdown 섹션을 반드시 사용할 것(아래 출력 포맷 준수).
        - 모델 간 **불일치(disagreement)**, **회색구간(gray zone)**을 반드시 포함.
        - 악성 혹은 회색 구간으로 판단 시 **운영 권고 체크리스트**를 반드시 포함.(정상일 경우에는 포함X)
        - 사용자가 쉽게 이해할 수 있도록 최대한 깔끔하고 조리있게 작성할 것

        # 불확실성 규칙
        - 최종 악성 확률(final_prob) 기준:
        - 고위험(> 70%): 적극 조치 권고.
        - 회색구간(40% ~ 60%): 보수적 판단, 추가 분석 권장. (※ 반드시 "회색구간" 문구 포함)
        - 저위험(< 30%): 정상 가능성이 높음. 단, 서브모델 불일치·의심 피처 있으면 보수적 권고 유지.
        - 서브모델 간 불일치:
        - 두 개 이상 모델이 서로 상충할 경우: "모달리티 간 신호 불일치"로 명시하고 원인 후보(피처 민감도/모달리티 차이)를 간단 기술.
        - 이 경우 최종 판단 문단에서 **불확실성↑**을 강조하고, 격리·추가 분석을 명확히 권고. 바이러스 토탈 등 교차 검증 사이트 제공할 것

        # 보안적 해석(가이드라인)
        - PE 피처:
        - strings_entropy↑ + base64_blob_count↑: 내장 데이터/인코딩/암호화 아티팩트 가능성(단정 금지).
        - imports_total vs import_dlls_unique: 소수 DLL에 호출 편중 → 특정 라이브러리 의존/래핑 가능성.
        - imports_max_per_dll↑: 특정 DLL 호출 집중(프록시/래핑) 가능성.
        - YARA 패커 플래그(UPX/mpress/aspack 등) 1: 패킹/난독화 가능성. 0: 패킹 징후 미검출(비악성 보장 아님).
        - 피처 분석을 토대로 해당 실행파일이 할 가능성이 있는 행위 등일 반드시 제시할 것 
        - Opcode:
        - n-gram은 통계적 특징일 뿐 의미 과해석 금지. 분기/호출/검사 패턴 증가는 “상대적 경향”으로만 기술.
        - 피처 분석을 토대로 해당 실행파일이 할 가능성이 있는 행위 등일 반드시 제시할 것 
        - 이미지(바이너리 시각화):
        - 보조 신호임을 인지하고 있으나, 어떠한 근거로 악성/정상을 판단했는지 간략히 서술할 것(패밀리 유사성 비교 용도)
        - 대표 패밀리 이미지는 참고용이며 확률 제공 없음.
        - 종합:
        - 세 가지의 분석결과를 토대로 해당 실행파일이 어떤 행위를 할 지 가능성을 제시하고 그에 따른 대응 방안을 간략하게 제시할 것

        # 출력 포맷 (Markdown)
        # 악성 확률: {{final_prob%}} / 최종 판정: {{malicious|benign}}
        - Bayesian Log-Odds Soft Voting : PE={{w_pe}}, Opcode={{w_opcode}}, Image={{w_image}}
        - 서브모델 예측: PE={{pe_prob%}} / Opcode={{op_prob%}} / Image={{img_prob%}}
        - 모델 간 일치도: (예: 모두 정상으로 수렴 / 일부 불일치 → 불확실성 주석)
        - 회색구간 여부: (해당 시 명시)

        ## 주요 PE 피처 근거
        - 사용 피처(값이 존재하는 것만 표시, 수치도 같이 표시) : 
        DllCharacteristics, SizeOfStackReserve, AddressOfEntryPoint, Characteristics,
        SizeOfHeaders, SizeOfInitializedData, SizeOfUninitializedData, SizeOfStackCommit,
        SizeOfCode, BaseOfCode, SectionAlignment, FileAlignment, ImageBase,
        PointerToSymbolTable, NumberOfSymbols, imports_total, imports_unique,
        import_dlls_unique, imports_max_per_dll, strings_avg_len, strings_base64_blob_count,
        e_minalloc, e_ovno, MinorImageVersion, MajorImageVersion,
        MajorOperatingSystemVersion, MinorSubsystemVersion, MajorLinkerVersion,
        NumberOfSections, Machine, imports_entropy, strings_entropy,
        strings_printable_ratio, yara_has_packer_generic, yara_count_packer,
        yara_has_upx_like, yara_has_mpress_like, yara_has_aspack_like, e_lfanew

        - 요약 작성 규칙:
            1. **문자열/인코딩/암호화 관련**
            - strings_entropy ↑, strings_printable_ratio ↓, strings_base64_blob_count ↑ → 내장 데이터/인코딩/암호화 아티팩트 가능성
            2. **DLL/Imports 관련**
            - imports_total, import_dlls_unique, imports_max_per_dll → 소수 DLL에 호출 집중 시 특정 라이브러리 의존/래핑 가능성
            - imports_entropy ↑ → 호출 패턴 다양성/난독화 가능성
            3. **헤더/섹션/이미지 관련**
            - SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, NumberOfSections, SectionAlignment → PE 구조 이상 여부, 패킹/난독화 징후 가능성
            - ImageBase, FileAlignment, BaseOfCode → 메모리 레이아웃 특이점 가능성
            4. **YARA/패킹 플래그**
            - yara_has_* 플래그 1 → 난독화/패킹 가능성
            - yara_count_packer → 패킹 탐지 횟수
            5. **기타 PE 헤더**
            - DllCharacteristics, AddressOfEntryPoint, e_lfanew 등 → 일반적 구조와 차이 발생 시 의심

        - 작성 지침:
            - 피처 수치를 기반으로 3~5문장 정도로 “가능성 중심” 기술  
            - 단정적 판단 금지, 예: “~ 가능성”, “~ 의심”, “정황상 ~”  
            - TF-IDF처럼 수치가 높은 피처는 중요성을 강조 가능  
            - 필요 시 “이 피처 단독으로 악성/정상 판단 불가” 명시
            - 판단한 근거들로 일어날 수 있는 실행파일의 행위를 반드시 제공할 것

        ## 주요 Opcode 근거
        - 대표 n-그램 상위 5개 (TF-IDF 점수 기준): 
        예시)- `mov mov mov` (0.32) → 반복적인 레지스터 이동, 초기화/루프 패턴 가능
             - `push call mov` (0.21) → 함수 호출 직전 스택/레지스터 조작, 복잡한 제어 흐름 시사
             - `push push push` (0.19) → 스택 기반 데이터 준비, 함수 호출 전 단계 가능
             - `call mov mov` (0.15) → 연속 호출 및 레지스터 이동, 제어 흐름 복잡성 반영
             - `push mov call` (0.12) → 스택+레지스터 조합, API 호출 패턴 가능
        - 요약: 각 n-그램은 TF-IDF 기반 통계적 중요도를 나타냅니다.  
                반복 이동, 스택/레지스터 조작 등은 악성코드에서 흔히 관찰되는 패턴이지만, 통계적 특징이므로 단정적 판단은 어렵습니다.
        - opcode 분석 결과가 없다면 : "Opcode 분석 결과가 존재하지 않아, 본 항목은 판단에 반영되지 않았습니다." 라고 출력

        ## 이미지 근거(바이너리 시각화)
        - 이미지 기반 확률: {{img_prob%}}, 보조 지표(있으면 간략히)
        - 요약: 보조 근거임을 명시하나 간략하게 판단 근거를 제시할 것. 대표 패밀리 이미지는 유사성 비교용(확률 제공 없음)
        - 이미지 분석 결과가 없다면 : "이미지 분석 결과가 존재하지 않아, 본 항목은 판단에 반영되지 않았습니다." 라고 출력

        ## 전체 요약 / 권고
        - 종합 판단(한 문단): 최종 확률, 서브모델 일치/불일치, 핵심 근거 요약. 
        - 운영 권고(체크리스트 형태로 그대로 나열):
        - [ ] 격리 및 백업
        - [ ] 추가 정적 분석
        - [ ] 샌드박스 동적 분석
        - [ ] 네트워크 차단/IoC 조회
        - [ ] VirusTotal 업로드(https://www.virustotal.com/gui/home/upload)

        JSON 데이터:
        {json.dumps(final_report, ensure_ascii=False, indent=2)}
        """

        # 5️⃣ Bedrock 모델 직접 호출
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 5000,
            "temperature": 0.7,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        try:
            response = bedrock.invoke_model(
                modelId="anthropic.claude-3-haiku-20240307-v1:0",
                body=json.dumps(payload),
                contentType="application/json",
                accept="application/json"
            )

            response_body = json.loads(response["body"].read())
            summary_text = response_body["content"][0]["text"].strip()

        except Exception as e:
            summary_text = f"[LLM 호출 오류] {str(e)}"

        # 6️⃣ 결과 JSON 구성
        result_json = {
            "label": label,
            "score_benign": score_benign,
            "score_malicious": score_malicious,
            "summary": summary_text
        }

        # 7️⃣ 결과 S3 업로드
        base = os.path.splitext(os.path.basename(key))[0]
        output_key = f"Bedrock_Report/{base}.json"
        tmp_output = "/tmp/final_result.json"

        with open(tmp_output, "w", encoding="utf-8") as f:
            json.dump(result_json, f, ensure_ascii=False, indent=2)

        s3.upload_file(tmp_output, bucket, output_key)
        print(f"✅ Report saved to s3://{bucket}/{output_key}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Bedrock final report generated (LangChain-free)",
                "output_s3_path": f"s3://{bucket}/{output_key}"
            }, ensure_ascii=False)
        }

    except Exception as e:
        print("❌ Error:", str(e))
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}