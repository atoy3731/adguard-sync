FROM alpine:3.13

ENV PYTHONUNBUFFERED=1

RUN apk update && \
    apk add python3 curl && \
    curl --silent --show-error --retry 5 https://bootstrap.pypa.io/get-pip.py | python3 && \
    apk del curl

COPY requirements.txt /tmp/requirements.txt

RUN pip3 install -r /tmp/requirements.txt && \
    rm -f /tmp/requirements.txt

COPY src /opt/app

WORKDIR /opt/app

ENTRYPOINT ["python3"]
CMD ["app.py"]

