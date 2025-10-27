# 베이스 이미지: OpenJDK 21 (Debian 12 기반)
FROM openjdk:21-jdk-slim

# 작업 디렉토리 설정
WORKDIR /opt

# ----------------------------------------------------
# 1️⃣ 필수 패키지 설치 + AWS CLI 강제 설치 (--break-system-packages)
# ----------------------------------------------------
RUN apt-get update && \
    apt-get install -y unzip wget curl python3 python3-pip && \
    pip install --break-system-packages awscli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------
# 2️⃣ Ghidra 복사 (이미 Docker context 내부에 폴더 포함되어 있음)
# ----------------------------------------------------
COPY ghidra_11.4.2_PUBLIC /opt/ghidra_11.4.2_PUBLIC

# ----------------------------------------------------
# 3️⃣ 분석 스크립트 및 실행 스크립트 복사
# ----------------------------------------------------
COPY run_one.sh /opt/
COPY scripts/export_asm.py /opt/scripts/export_asm.py

# ----------------------------------------------------
# 4️⃣ 환경 변수 설정 (Lambda/Fargate 비대화식 환경 대응)
# ----------------------------------------------------
ENV JAVA_HOME=/usr/local/openjdk-21
ENV PATH=$JAVA_HOME/bin:$PATH
ENV GHIDRA_HOME=/opt/ghidra_11.4.2_PUBLIC
ENV PYTHONUNBUFFERED=1

# ----------------------------------------------------
# 5️⃣ Ghidra launch.sh 수정 (TTY 비검출 문제 해결)
# ----------------------------------------------------
RUN sed -i 's|JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64|JAVA_HOME=/usr/local/openjdk-21|' \
    /opt/ghidra_11.4.2_PUBLIC/support/launch.sh && \
    chmod +x /opt/ghidra_11.4.2_PUBLIC/support/launch.sh && \
    chmod +x /opt/run_one.sh

# ----------------------------------------------------
# 6️⃣ 기본 실행 스크립트 설정
# ----------------------------------------------------
WORKDIR /opt
ENTRYPOINT ["/bin/bash", "run_one.sh"]
