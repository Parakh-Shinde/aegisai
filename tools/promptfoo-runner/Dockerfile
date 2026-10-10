FROM node:22-alpine

ARG PROMPTFOO_VERSION=0.124.1
ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    PROMPTFOO_DISABLE_TELEMETRY=true \
    PROMPTFOO_DISABLE_UPDATE_CHECK=true \
    AEGISAI_PROMPTFOO_VERSION=${PROMPTFOO_VERSION}

RUN npm install --global --omit=dev "promptfoo@${PROMPTFOO_VERSION}" \
    && mkdir /work \
    && chown node:node /work

WORKDIR /work
COPY runner.mjs /opt/aegisai/runner.mjs

USER node
ENTRYPOINT ["node", "/opt/aegisai/runner.mjs"]
