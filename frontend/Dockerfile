FROM node:22-alpine AS build

WORKDIR /app

COPY package.json ./
COPY package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . ./

ARG VITE_API_BASE_URL=http://127.0.0.1:8000
ARG VITE_AUTH_REQUIRED=false
ARG VITE_ASYNC_CAMPAIGNS=false
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_AUTH_REQUIRED=$VITE_AUTH_REQUIRED
ENV VITE_ASYNC_CAMPAIGNS=$VITE_ASYNC_CAMPAIGNS

RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
