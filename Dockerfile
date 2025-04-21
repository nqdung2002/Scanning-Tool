################ 1. BUILD DEPENDENCIES ################
FROM python:3.13-slim AS builder
WORKDIR /app

# Tạo venv riêng
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Cài thư viện Python
COPY requirements.txt .
RUN pip install -U pip && \
    pip install -r requirements.txt

################ 2. RUNTIME IMAGE ################
FROM python:3.13-slim
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# chép venv đã cài sẵn package
COPY --from=builder $VIRTUAL_ENV $VIRTUAL_ENV

# chép mã nguồn app
WORKDIR /app
COPY . .

# cài thêm các binary cần thiết (Nuclei)
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.6/nuclei_3.2.6_linux_amd64.zip && \
    unzip nuclei_3.2.6_linux_amd64.zip -d /usr/local/bin && \
    rm nuclei_3.2.6_linux_amd64.zip && \
    nuclei -ut -silent

# Cài thư viện hệ thống cho SSL, DNS, và Firefox headless
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl dnsutils \
      libgtk-3-0 libdbus-glib-1-2 libdbus-1-3 libxt6 libx11-6 libxrender1 \
      firefox-esr && \
    rm -rf /var/lib/apt/lists/*

# Cài geckodriver thủ công từ GitHub
ARG GECKO_VERSION=v0.36.0
RUN curl -sL \
      "https://github.com/mozilla/geckodriver/releases/download/${GECKO_VERSION}/geckodriver-${GECKO_VERSION}-linux64.tar.gz" \
    | tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/geckodriver


EXPOSE 5000
CMD ["python", "./run.py"]
