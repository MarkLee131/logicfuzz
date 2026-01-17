# Build a virtualenv using the appropriate Debian release:
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Singapore \
    VIRTUAL_ENV=/venv \
    PATH="/venv/bin:$PATH" \
    PYTHONPATH="/experiment"

ARG INSTALL_HOST_CLI=true

# Install base packages and create the virtualenv.
RUN apt-get update && \
    apt-get install --no-install-recommends --yes \
    python3-venv \
    gcc \
    libpython3-dev \
    git \
    apt-transport-https \
    ca-certificates \
    gnupg \
    curl \
    wget2 \
    clang-format && \
    python3 -m venv /venv && \
    rm -rf /var/lib/apt/lists/*

# Install Docker CLI (talking to host daemon) when needed.
RUN if [ "$INSTALL_HOST_CLI" = "true" ]; then \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    RELEASE_CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME") && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${RELEASE_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install --no-install-recommends --yes \
    docker-ce-cli \
    docker-buildx-plugin \
    docker-compose-plugin && \
    rm -rf /var/lib/apt/lists/*; \
    else \
    echo "Skipping Docker/gcloud CLI install."; \
    fi

WORKDIR /experiment

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY . .

# ENTRYPOINT ["python3", "./report/docker_run.py"]
