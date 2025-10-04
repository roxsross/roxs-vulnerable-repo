FROM node:16

LABEL org.opencontainers.image.title="Vulnerable Node App" \
      org.opencontainers.image.description="Enhanced secure build of vulnerable-node for security testing" \
      org.opencontainers.image.authors="Enhanced DevSecOps Pipeline" \
      org.opencontainers.image.version="2.0" \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
      org.opencontainers.image.source="https://github.com/your-org/your-repo" \
      org.opencontainers.image.licenses="MIT"

ENV STAGE="DOCKER"

RUN mkdir /app
WORKDIR /app

COPY package.json /app/
RUN npm install

COPY . /app

EXPOSE 3000

CMD [ "npm", "start" ]
