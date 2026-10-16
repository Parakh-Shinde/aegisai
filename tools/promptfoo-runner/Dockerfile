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
RUN printf '{"name":"aegisai-promptfoo-runner","private":true,"dependencies":{"promptfoo":"%s"},"overrides":{"basic-ftp":"6.2.1","undici":"6.28.1","ip-address":"10.3.1","picomatch@^4.0.0":"4.0.4","brace-expansion@^1.0.0":"1.1.20","brace-expansion@^2.0.0":"2.1.6","brace-expansion@^3.0.0":"3.0.8","brace-expansion@^5.0.0":"5.0.11"}}' "$PROMPTFOO_VERSION" > package.json \
    && npm install --omit=dev --no-audit --no-fund \
    && npm ls basic-ftp brace-expansion ip-address picomatch \
    && promptfoo --version \
    # npm is only needed during image construction; remove its vulnerable bundled tree from runtime. \
    && rm -rf /usr/local/lib/node_modules/npm

COPY runner.mjs /opt/aegisai/runner.mjs

USER node
ENTRYPOINT ["node", "/opt/aegisai/runner.mjs"]
