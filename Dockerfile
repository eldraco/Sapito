FROM python:3.9-slim

LABEL org.opencontainers.image.authors="vero.valeros@gmail.com,eldraco@gmail.com"

ENV DESTINATION_DIR /sapito

COPY . ${DESTINATION_DIR}/

RUN pip install -r ${DESTINATION_DIR}/requirements.txt

WORKDIR ${DESTINATION_DIR}
