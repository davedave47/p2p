FROM python:3.12.7-slim

WORKDIR /app

COPY . /app

RUN mkdir -p /data && chmod -R 777 /data

RUN pip install -r requirements.txt

CMD ["python", "Tracker.py"]