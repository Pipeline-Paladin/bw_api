FROM node:16-alpine as build

WORKDIR /build

COPY package.json ./
COPY package-lock.json ./
RUN npm ci

COPY . .
RUN npm run ng build
RUN find dist/ -type f -print -exec chmod 644 {} +


FROM nginx:1.21-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /build/dist/bw_api /var/www/static/


