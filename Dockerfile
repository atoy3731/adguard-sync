FROM alpine:latest

ENV PYTHONUNBUFFERED=1

RUN apk update && \
    apk add --no-cache python3 py3-pip && \
    rm -rf /var/cache/apk/*

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm -f /tmp/requirements.txt

COPY src /opt/app

WORKDIR /opt/app

ENTRYPOINT ["python"]
CMD ["app.py"]