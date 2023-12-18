FROM ubuntu:22.04

RUN apt update && apt install -y socat python3-pip

WORKDIR /app

RUN mkdir /app/src

COPY src src

CMD ["socat", "TCP-LISTEN:56789,reuseaddr,fork", "EXEC:/app/src/entry.sh"]