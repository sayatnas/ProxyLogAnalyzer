FROM python:3.13-slim

WORKDIR /app

# Dependencies are copied and installed before the source code so Docker can
# reuse the cached install layer when only application code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Cloud Run and most platforms tell the app which port to listen on.
ENV PORT=5000
EXPOSE 5000

CMD ["python", "app.py"]
