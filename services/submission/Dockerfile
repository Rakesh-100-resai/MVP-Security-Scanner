FROM python:3.11-slim

WORKDIR /app

# Create log dir
RUN mkdir -p /var/log/mvp-scanner

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
