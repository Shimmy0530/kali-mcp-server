FROM kalilinux/kali-rolling:latest

# Noninteractive to avoid tzdata prompts, etc.
ENV DEBIAN_FRONTEND=noninteractive
# Unbuffered Python output for immediate response in MCP protocol
ENV PYTHONUNBUFFERED=1

# Base system + GPG key + Python
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated \
        ca-certificates \
        gnupg2 \
        python3 \
        python3-pip \
        git && \
    gpg --keyserver keyserver.ubuntu.com --recv-keys 827C8569F2518CC677FECA1AED65462EC8D5E4C5 && \
    gpg --export 827C8569F2518CC677FECA1AED65462EC8D5E4C5 > /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg && \
    apt-get update

# Install Kali metapackages and specific tools used in mcp_server.py
# - kali-linux-default: core pentest stack
# - kali-tools-web: web app tooling (nikto, wapiti, gobuster, ffuf, zap, etc.)
# - kali-tools-vulnerability: additional scanners
# - kali-tools-database: DB tooling to complement sqlmap
# - kali-tools-passwords: hydra/medusa/etc. if you later add auth tools
RUN apt-get install -y \
        kali-linux-default \
        kali-tools-web \
        kali-tools-vulnerability \
        kali-tools-database \
        kali-tools-passwords \
        libcap2-bin \
        # Explicitly ensure tools referenced in mcp_server.py are present
        nmap \
        nikto \
        sqlmap \
        wpscan \
        dirb \
        wfuzz \
        whatweb \
        theharvester \
        recon-ng \
        masscan \
        dnsenum \
        dnsrecon \
        wapiti \
        skipfish \
        gobuster \
        ffuf \
        uniscan \
        zaproxy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Fix nmap permissions - set capabilities for raw socket access
# Container should be run with: --cap-add=NET_RAW --cap-add=NET_ADMIN
RUN chmod +x /usr/bin/nmap && \
    chmod +x /usr/lib/nmap/nmap || true && \
    (setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap 2>/dev/null || true) && \
    (setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/lib/nmap/nmap 2>/dev/null || true)

# Python deps for MCP server
RUN pip3 install --break-system-packages \
        mcp \
        python-dotenv \
        uvicorn

# Copy MCP server and entrypoint
WORKDIR /app
COPY mcp_server.py /app/mcp_server.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose MCP SSE port
EXPOSE 8000

# Use entrypoint script to handle different modes
ENTRYPOINT ["/app/entrypoint.sh"]
