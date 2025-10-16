# Use a standard Node.js runtime as the base image
FROM node:20-slim

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev \
    && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /root/.npm \
    && [ ! -d /usr/local/lib/node_modules ]

COPY . .

CMD ["node", "run_eval.js"]
