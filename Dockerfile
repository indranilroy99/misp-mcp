# misp-mcp container image.
# Runs the hosted HTTP transport by default (MCP_TRANSPORT=http), bound to
# 0.0.0.0:8080. TLS is terminated upstream (ALB / reverse proxy), so the
# process serves plain HTTP and requires MISP_MCP_ALLOW_INSECURE_BIND=true
# at run time when bound to a non-loopback address.
FROM python:3.12-slim

WORKDIR /app

# Install the package (deps resolved from pyproject.toml) + the misp-mcp binary.
COPY . .
RUN pip install --no-cache-dir -e .

# Defaults for hosted mode; override the rest (MISP_URL, etc.) at run time.
ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080

EXPOSE 8080

# Console entry point (misp_mcp.server:main) — dispatches by MCP_TRANSPORT.
CMD ["misp-mcp"]
