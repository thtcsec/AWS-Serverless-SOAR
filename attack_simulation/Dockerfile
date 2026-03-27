FROM ubuntu:24.04

# Avoid tzdata interactive prompt
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    curl \
    python3 \
    python3-pip \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip ./aws

# Setup Workdir
WORKDIR /attacks

# Copy all scripts to the container
COPY scripts/ /attacks/scripts/
COPY menu.sh /attacks/menu.sh

# Make sure shell scripts are executable
RUN chmod +x /attacks/scripts/*.sh /attacks/menu.sh

ENTRYPOINT ["/attacks/menu.sh"]
