# Base image
FROM python:3.9-slim

WORKDIR /app

# Installing dependencies
RUN pip install prometheus_client dotenv

# Copying the exporter script
COPY trivy_exporter_docker.py ./trivy_exporter.py

# Creating a directory for scans
RUN mkdir -p /scans

# The port that the exporter will listen to
EXPOSE 8000

# Launch command
CMD ["python", "trivy_exporter.py", "--scan-dir", "/scans", "--port", "8000"]
