# Use official lightweight Python image
FROM python:3.11-slim

# Set environment variables
ARG MAXMIND_URL
ARG BUCKET_NAME
ARG BLOB_NAME
ARG BQ_DATASET
ARG BQ_IPV4_TABLE
ARG BQ_IPV6_TABLE

ENV MAXMIND_URL=$MAXMIND_URL
ENV BUCKET_NAME=$BUCKET_NAME
ENV BLOB_NAME=$BLOB_NAME
ENV BQ_DATASET=$BQ_DATASET
ENV BQ_IPV4_TABLE=$BQ_IPV4_TABLE
ENV BQ_IPV6_TABLE=$BQ_IPV6_TABLE

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port for Cloud Run
EXPOSE 8080

# Set entrypoint for Flask app
CMD ["gunicorn", "-b", "0.0.0.0:8080", "main:app"]