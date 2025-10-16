# Use a standard Node.js runtime as the base image
FROM node:20-slim@sha256:f679d7699517426eb148a5698c717477fd3f8a48f6c1eaf771e390a9bb8268c8

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev \
    && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /root/.npm \
    && [ ! -d /usr/local/lib/node_modules ]

COPY . .

RUN useradd --create-home --home-dir /home/evaluator --uid 10001 --gid 0 evaluator \
    && chown -R evaluator:0 /app /home/evaluator \
    && chmod -R g=u /app /home/evaluator

USER evaluator

CMD ["node", "run_eval.js"]
