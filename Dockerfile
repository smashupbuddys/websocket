FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev

COPY index.js ./
COPY config.json ./

RUN mkdir -p logs && chown node:node logs

EXPOSE 8001

USER node

CMD ["npm", "start"]