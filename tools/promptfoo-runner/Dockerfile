FROM node:22-alpine

ARG PROMPTFOO_VERSION=0.124.1
ENV NODE_ENV=production \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_DATA_HOME=/tmp/.local/share \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    PROMPTFOO_DISABLE_TELEMETRY=true \
    PROMPTFOO_DISABLE_UPDATE_CHECK=true \
    AEGISAI_PROMPTFOO_VERSION=${PROMPTFOO_VERSION}

RUN npm install --global --omit=dev "promptfoo@${PROMPTFOO_VERSION}"

WORKDIR /tmp
COPY runner.mjs /opt/aegisai/runner.mjs

USER node
ENTRYPOINT ["node", "/opt/aegisai/runner.mjs"]
