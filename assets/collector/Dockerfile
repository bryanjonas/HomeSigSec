FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir websockets==12.0
COPY eventbus_collect.py /app/eventbus_collect.py
COPY db.py /app/db.py
EXPOSE 0
CMD ["python", "/app/eventbus_collect.py"]
