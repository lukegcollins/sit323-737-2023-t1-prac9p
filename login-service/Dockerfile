FROM node:16-slim

WORKDIR /user/src/app

COPY package*.json ./

RUN npm install

COPY app.js ./
COPY *.pem ./

EXPOSE 3000
CMD [ "node", "app.js" ]