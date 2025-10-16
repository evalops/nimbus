FROM registry.access.redhat.com/ubi9/nodejs-20@sha256:938970e0012ddc784adda181ede5bc00a4dfda5e259ee4a57f67973720a565d1 AS web-build

ENV NODE_ENV=production

WORKDIR /app

USER 0
RUN useradd --no-log-init --create-home --home-dir /home/webbuild --uid 10001 --gid 0 webbuild
RUN chown webbuild:0 /app

USER webbuild

COPY --chown=webbuild:0 web/package.json web/package-lock.json ./
RUN npm ci

COPY --chown=webbuild:0 web ./
RUN npm run build

FROM registry.access.redhat.com/ubi9/python-312@sha256:f17b0788b7eff1683ff8ba7c6a17b907648753d489e8d7d3975eaf6c41644287

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    SYSTEMCRYPTOFIPS=1

WORKDIR /app

USER 0

RUN dnf update -y \
    && dnf install -y \
        openssl \
        crypto-policies-scripts \
        policycoreutils-python-utils \
        selinux-policy-targeted \
        shadow-utils \
        tar \
        gzip \
    && update-crypto-policies --set FIPS \
    && dnf clean all

RUN useradd --no-log-init --create-home --home-dir /var/lib/nimbus nimbus

COPY pyproject.toml uv.lock ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install --no-cache-dir . \
    && rm -rf /usr/local/lib/node_modules /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx \
    && [ ! -d /usr/local/lib/node_modules ]

COPY README.md ./
COPY --from=web-build /app/dist ./web/dist

RUN chown -R nimbus:nimbus /app /var/lib/nimbus

USER nimbus

CMD ["uvicorn", "nimbus.control_plane.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
