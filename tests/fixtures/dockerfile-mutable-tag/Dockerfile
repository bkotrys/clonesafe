FROM node:latest

WORKDIR /app
COPY package*.json ./

RUN curl -fsSL https://example.com/install.sh | bash

COPY . .
CMD ["node", "index.js"]
