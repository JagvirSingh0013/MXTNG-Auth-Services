FROM python:3.13-slim

WORKDIR /app

# Install deps first for layer caching.
COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY migrations ./migrations
RUN pip install --no-cache-dir ".[postgres,google]"

ENV ENVIRONMENT=production
EXPOSE 8100

CMD ["uvicorn", "mxtng_auth.main:app", "--host", "0.0.0.0", "--port", "8100"]
