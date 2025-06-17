FROM denoland/deno:latest

ARG GIT_REVISION
ENV DENO_DEPLOYMENT_ID=${GIT_REVISION}

WORKDIR /app

COPY . .

EXPOSE 8000

RUN apt-get update && apt-get install -y sqlite3

RUN deno task build

CMD ["run", "-A", "main.ts"]