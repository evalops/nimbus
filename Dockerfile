FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install --no-cache-dir .

COPY README.md ./

CMD ["uvicorn", "smith.control_plane.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
