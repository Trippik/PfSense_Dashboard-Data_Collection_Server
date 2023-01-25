FROM ubuntu:20.04

MAINTAINER Cameron Trippick "trippickc@gmail.com"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev


COPY ./requirements.txt /requirements.txt

COPY ./setup.py /setup.py

WORKDIR /

RUN python3 setup.py install

COPY . /

ENTRYPOINT [ "python3" ]

CMD [ "syslog_server/app.py" ]