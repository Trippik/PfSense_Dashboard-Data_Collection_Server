FROM ubuntu:23.04

MAINTAINER Cameron Trippick "trippickc@gmail.com"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev


COPY ./requirements.txt /requirements.txt

COPY ./setup.py /setup.py

COPY . /

WORKDIR /

RUN python3 setup.py install

CMD [ "PfSense_Dashboard-Data_Collection_Server" ]