FROM ubuntu:23.04

MAINTAINER Cameron Trippick "trippickc@gmail.com"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev


COPY ./requirements.txt /requirements.txt

COPY ./setup.py /setup.py

COPY . /

WORKDIR /

RUN python3 setup.py install

ENV DB_IP = "Placeholder"

ENV DB_USER = "Placeholder"

ENV DB_PASS = "Placeholder"

ENV DB_SCHEMA = "Placeholder"

ENV DB_PORT = "Placeholder"

ENV SYSLOG_POLL_INTERVAL = "Placeholder"

ENV SSH_POLL_INTERVAL = "Placeholder"

CMD [ "PfSense_Dashboard-Data_Collection_Server" ]

