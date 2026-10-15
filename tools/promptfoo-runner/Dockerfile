FROM node:24-alpine3.24

ARG PROMPTFOO_VERSION=0.124.1
ENV NODE_ENV=production \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_DATA_HOME=/tmp/.local/share \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    PROMPTFOO_DISABLE_TELEMETRY=true \
    PROMPTFOO_DISABLE_UPDATE_CHECK=true \
    AEGISAI_PROMPTFOO_VERSION=${PROMPTFOO_VERSION} \
    PATH=/opt/aegisai/node_modules/.bin:$PATH

WORKDIR /opt/aegisai

# Override the affected transitive dependency until Promptfoo publishes a patched
# dependency tree; the CI image scan verifies the resolved production tree.
RUN npm init -y \
    && npm pkg set "dependencies.promptfoo=${PROMPTFOO_VERSION}" \
        "overrides.basic-ftp=6.2.1" \
    && npm install --omit=dev --no-audit --no-fund \
    && npm ls basic-ftp \
    && promptfoo --version

COPY runner.mjs /opt/aegisai/runner.mjs

USER node
ENTRYPOINT ["node", "/opt/aegisai/runner.mjs"]
