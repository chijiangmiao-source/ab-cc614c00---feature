FROM node:20-alpine

WORKDIR /app

COPY package.json ./
COPY build.js server.js ./
COPY src ./src
COPY test ./test
COPY verify ./verify

# 构建页面产物（语法校验 + dist/）
RUN node build.js

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
