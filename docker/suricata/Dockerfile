FROM alpine:latest
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories
RUN apk add --no-cache \
    python \
    suricata \
    py-pip \
    git

RUN git clone https://github.com/OISF/suricata
RUN cp suricata/python/suricata/config/defaults.py.in suricata/python/suricata/config/defaults.py

WORKDIR /suricata/python
RUN python setup.py install

WORKDIR /app
COPY . /app
RUN pip install -r /app/requirements.txt
ENTRYPOINT ["python", "suri.py"]