FROM python:3.12-bookworm
COPY /requirements.txt /
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y postgresql-client
COPY /orders /app/orders
COPY /scripts /scripts
RUN apt-get install dos2unix
RUN dos2unix /scripts/*
WORKDIR /app
ENTRYPOINT ["bash", "/scripts/run_app.sh"]