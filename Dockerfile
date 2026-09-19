FROM python:3.13-slim

WORKDIR /app

# Install deps first for layer caching.
COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY migrations ./migrations
RUN pip install --no-cache-dir ".[postgres,google]"

ENV ENVIRONMENT=production

# Drop root (SECURITY_AUDIT H-6). The signing key and every secret in the
# environment are reachable from this process; there is no reason for it to also
# be able to write the image.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8100

# --proxy-headers plus a trusted-proxy list is what makes TRUST_PROXY_HEADERS
# safe: X-Forwarded-For is honoured from the ingress and ignored from anyone
# else, so the audit trail and the rate limiter see real client addresses
# (SECURITY_AUDIT L-6). Override FORWARDED_ALLOW_IPS with the ingress subnet.
ENV FORWARDED_ALLOW_IPS="127.0.0.1"
CMD ["uvicorn", "mxtng_auth.main:app", "--host", "0.0.0.0", "--port", "8100", "--proxy-headers"]
