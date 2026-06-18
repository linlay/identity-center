ARG NODE_BUILD_IMAGE=node:20-alpine
ARG NGINX_IMAGE=nginx:1.27-alpine

FROM ${NODE_BUILD_IMAGE} AS ui-build
WORKDIR /app
ARG NPM_REGISTRY=https://registry.npmjs.org
ARG VITE_BASE_PATH=/admin/
ARG VITE_DEV_PORT=11950
ARG VITE_DEV_STRICT_PORT=true
ARG VITE_API_PROXY_PATH=/admin/api
ARG VITE_API_PROXY_TARGET=http://identity-center-backend:8080
ENV VITE_BASE_PATH=$VITE_BASE_PATH \
    VITE_DEV_PORT=$VITE_DEV_PORT \
    VITE_DEV_STRICT_PORT=$VITE_DEV_STRICT_PORT \
    VITE_API_PROXY_PATH=$VITE_API_PROXY_PATH \
    VITE_API_PROXY_TARGET=$VITE_API_PROXY_TARGET
COPY package.json package-lock.json ./
RUN npm config set registry "$NPM_REGISTRY" && npm ci
COPY . .
RUN npm run build

FROM ${NGINX_IMAGE}
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=ui-build /app/dist /usr/share/nginx/html
EXPOSE 80
