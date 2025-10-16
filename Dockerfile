FROM registry.access.redhat.com/ubi9/nodejs-20:latest AS web-build

ENV NODE_ENV=production

WORKDIR /app

USER 0

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web ./
RUN npm run build

FROM registry.access.redhat.com/ubi9/python-312:latest

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    SYSTEMCRYPTOFIPS=1

WORKDIR /app

RUN microdnf update -y \
    && microdnf install -y \
        openssl \
        openssl-perl \
        fipscheck \
        crypto-policies-scripts \
        policycoreutils-python-utils \
        selinux-policy-targeted \
        shadow-utils \
        tar \
        gzip \
    && update-crypto-policies --set FIPS \
    && microdnf clean all

RUN useradd --no-log-init --create-home --home-dir /var/lib/nimbus nimbus

COPY pyproject.toml uv.lock ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install --no-cache-dir .

COPY README.md ./
COPY --from=web-build /app/dist ./web/dist

RUN chown -R nimbus:nimbus /app /var/lib/nimbus

USER nimbus

CMD ["uvicorn", "nimbus.control_plane.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
