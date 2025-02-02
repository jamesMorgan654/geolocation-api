import requests
from flask import Flask, request, jsonify
from google.cloud import storage, bigquery, secretmanager
from requests.auth import HTTPBasicAuth
import ipaddress
import csv
import os
import zipfile
import io
from google.auth import default
import re
import time

app = Flask(__name__)

# Get the default project ID
_, PROJECT_ID = default()

def get_secret(secret_name):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest" #Can you default to the current project id?
    response = client.access_secret_version(name=name)
    return response.payload.data.decode("UTF-8")

# Load secrets
secrets = dict(line.split("=", 1) for line in get_secret("geolocation-webhook").split("\n"))
API_KEY = secrets.get("API_KEY")
MAXMIND_ACCOUNT_ID = secrets.get("MAXMIND_ACCOUNT_ID")
MAXMIND_LICENSE_KEY = secrets.get("MAXMIND_LICENSE_KEY")
# Load Vars
MAXMIND_URL = os.environ.get("MAXMIND_URL")
BUCKET_NAME = os.environ.get("BUCKET_NAME")
BLOB_NAME = os.environ.get("BLOB_NAME")
BQ_DATASET = os.environ.get("BQ_DATASET")
BQ_IPV4_TABLE = os.environ.get("BQ_IPV4_TABLE")
BQ_IPV6_TABLE = os.environ.get("BQ_IPV6_TABLE")

storage_client = storage.Client()

def require_auth(func):
    """Decorator to require API key authentication."""
    def wrapper(*args, **kwargs):
        if API_KEY:
            auth_header = request.headers.get("Authorization")
            if not auth_header or auth_header != f"Bearer {API_KEY}":
                return jsonify({"error": "Unauthorized"}), 401
            return func(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    wrapper.__name__ = func.__name__  
    return wrapper

def fetch_zip():
    """Get the ZIP file and save to cloud storage bucket"""
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"{BLOB_NAME}.zip")

        response = requests.get(
            MAXMIND_URL,
            auth=HTTPBasicAuth(MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY),
            stream=True  # Stream the response to avoid loading it all in memory
        )
        response.raise_for_status()

        # Stream upload to GCS

        with io.BytesIO() as buffer:
            for chunk in response.iter_content(chunk_size=8192):
                buffer.write(chunk)
            buffer.seek(0)
            blob.upload_from_file(buffer, content_type="application/zip")

        return True

    except Exception as e:
        print(f"Error fetching ZIP: {e}")
        return False

def get_zip_date():
    """Extract the date from the ZIP contents (e.g., GeoLite2-City-CSV_YYYYMMDD)."""
    bucket = storage_client.bucket(BUCKET_NAME)
    zip_blob = bucket.blob(f"{BLOB_NAME}.zip")

    # Reads metadata from ZIP
    with zipfile.ZipFile(io.BytesIO(zip_blob.download_as_bytes()), 'r') as zip_ref:
        for file_name in zip_ref.namelist():
            match = re.search(r"GeoLite2-City-CSV_(\d{8})", file_name)
            if match:
                return match.group(1)  # Extract YYYYMMDD date
            
def get_latest_gcs_date():
    """Find the most recent date-based folder in GCS."""
    bucket = storage_client.bucket(BUCKET_NAME)

    blobs = list(bucket.list_blobs(prefix=f"{BLOB_NAME}_unzipped/"))

    folder_dates = set()
    pattern = re.compile(r"GeoLite2-City-CSV_(\d{8})/")  # YYYYMMDD format

    for blob in blobs:
        match = pattern.search(blob.name)
        if match:
            folder_dates.add(match.group(1))

    return max(folder_dates) if folder_dates else None

def extract_zip():
    try:
        # Checks to see if there is already a file there
        zip_date = get_zip_date()
        latest_gcs_date = get_latest_gcs_date()
        if zip_date == latest_gcs_date:
            return "FOLDER_EXISTS"  
        
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"{BLOB_NAME}.zip")
        zip_bytes = blob.download_as_bytes()

        with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zip_ref:
            for file_name in zip_ref.namelist():
                file_blob = bucket.blob(f"{BLOB_NAME}_unzipped/{file_name}")
                with zip_ref.open(file_name) as file_data:
                    file_blob.upload_from_file(file_data)    
        # Cleanup
        blob.delete()
        return True
    except Exception as e:
        print(f"Error extracting ZIP: {e}")
        return False

def get_latest_folder():
    """Find the latest date-based folder in GCS under `geodata_unzipped/`."""
    latest_gcs_date = get_latest_gcs_date()
    if not latest_gcs_date:
        raise ValueError("No valid date-based folders found in GCS.")
    return f"GeoLite2-City-CSV_{latest_gcs_date}/"

def wait_for_gcs_file(file):
    """Wait until the file appears in GCS (max 30 seconds)."""
    bucket = storage_client.bucket(BUCKET_NAME)
    blob_path = f"{BLOB_NAME}_unzipped/{get_latest_folder()}{file['filename']}"
    blob = bucket.blob(blob_path)

    timeout = 30  # Max wait time in seconds
    start_time = time.time()

    while time.time() - start_time < timeout:
        if blob.exists():
            return True
        time.sleep(2)  # Wait before checking again

    print(f"Timeout: File {blob_path} did not appear in GCS within {timeout} seconds")
    return False

def get_csv_headers_from_gcs(file):
    """Reads CSV headers from GCS to generate a schema with all STRING fields."""
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(f"{BLOB_NAME}_unzipped/{get_latest_folder()}{file['filename']}")

    # Download only the first row of the CSV
    csv_data = blob.download_as_text(encoding="utf-8")
    first_line = csv_data.split("\n", 1)[0]  # Get only the first line

    # Parse CSV headers
    reader = csv.reader(io.StringIO(first_line))
    headers = next(reader)

    # Convert all headers into STRING schema
    schema = [bigquery.SchemaField(column, "STRING") for column in headers]
    
    return schema

def load_csv_to_bq(file):
    """Load CSV file from GCS into BigQuery."""
    client = bigquery.Client()
    table_id = f"{PROJECT_ID}.{BQ_DATASET}.{file['tablename']}" #Can you make this default to the current project id?
    latest_folder = get_latest_folder()
    uri = f"gs://{BUCKET_NAME}/{BLOB_NAME}_unzipped/{latest_folder}{file['filename']}"
    
    if not wait_for_gcs_file(file):  # Ensure file is in GCS before loading
        return False

    try:
        string_schema = get_csv_headers_from_gcs(file)
        job_config = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.CSV,
            skip_leading_rows=1,
            schema=string_schema, 
            max_bad_records=10,
            write_disposition="WRITE_TRUNCATE"
        )

        load_job = client.load_table_from_uri(uri, table_id, job_config=job_config)
        result =  load_job.result()
        if load_job.errors:
            print(f"BigQuery load job failed for table {table_id}")
            for error in load_job.errors:
                print(f"Error: {error['message']}")
            return False
        return True
    except Exception as e:
        print(f"Unexpected Exception while loading {file['filename']} into {table_id}: {e}")
        return False

def get_ip_version(ip):
    """Determine if the IP is IPv4 or IPv6."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return 4 if ip_obj.version == 4 else 6
    except ValueError:
        return None  # Invalid IP

def find_geoname_id(ip):
    """Determine if the IP is IPv4 or IPv6 and find its geoname_id and postal_code."""
    try:
        ip_version = get_ip_version(ip)
        table = BQ_IPV4_TABLE if ip_version == 4 else BQ_IPV6_TABLE
        bigquery_client = bigquery.Client()
        query = f"""
            WITH cidr_table AS (
            SELECT
                network,
                postal_code,
                latitude,
                longitude,
                NET.IPV4_TO_INT64(NET.IP_FROM_STRING(SPLIT(network, '/')[SAFE_OFFSET(0)])) AS network_int,
                32 - CAST(SPLIT(network, '/')[SAFE_OFFSET(1)] AS INT64) AS host_bits
            FROM
                `{PROJECT_ID}.{BQ_DATASET}.{table}`
            ),
            ip_table AS (
            SELECT
                '{ip}' AS ip_address,
                NET.IPV4_TO_INT64(NET.IP_FROM_STRING('{ip}')) AS ip_int
            ),
            ip_lookup AS (
            SELECT
                c.network,
                c.postal_code,
                c.latitude,
                c.longitude
            FROM
                cidr_table c
            JOIN
                ip_table i
            ON
                i.ip_int BETWEEN c.network_int AND (c.network_int + POW(2, c.host_bits) - 1)
            LIMIT 1
            )
            SELECT
            network,
            postal_code,
            latitude,
            longitude,
            locality,
            territory,
            country
            FROM (
            SELECT * FROM ip_lookup a
            LEFT JOIN
            (SELECT DISTINCT postcode, locality, territory, country FROM `{PROJECT_ID}.{BQ_DATASET}.postcodes`) b
            ON a.postal_code = b.postcode 
            ) LIMIT 1;
        """
        # Make query to bigquery and return json object
        query_job = bigquery_client.query(query)
        results = query_job.result()

        # Fetch results as JSON
        rows = [dict(row) for row in results]

        return rows[0] if rows else None  # Return first result or None if no match found

    except ValueError:
        return None, None  # Invalid IP
    except Exception:
        return None, None  # Handle unexpected errors

@app.route("/", methods=["GET"])    
@require_auth
def send_geo_data():
    # Get url param ip
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "Missing 'ip' parameter"}), 400  # Return error if IP is missing
    geo_data = find_geoname_id(ip)
    return jsonify({"data": geo_data}), 200

@app.route("/update", methods=["POST"])
@require_auth
def main():
    if not fetch_zip():
        return jsonify({"error": "Failed to fetch ZIP"}), 500
    zip_extracted = extract_zip()
    if not zip_extracted:
        return jsonify({"error": "Failed to extract ZIP"}), 500
    elif zip_extracted == "FOLDER_EXISTS":
        return jsonify({"success": "Data Exists"}), 202
    # Files that need to become bigquery tables
    files = [
        {"filename": "GeoLite2-City-Blocks-IPv4.csv", "tablename": "ipv4"}, 
        {"filename": "GeoLite2-City-Blocks-IPv6.csv", "tablename": "ipv6"}, 
        {"filename": "GeoLite2-City-Locations-en.csv", "tablename": "city_locations"}
    ]
    jobs = [load_csv_to_bq(file) for file in files]
    if all(jobs):
        return jsonify({"message": "Data successfully loaded into BigQuery"}), 200
    return jsonify({"error": "One or more BigQuery jobs failed"}), 500

@app.route("/", methods=["OPTIONS"])
def options():
    """Handles preflight OPTIONS requests for CORS support."""
    response = jsonify({"message": "Allowed methods: OPTIONS, POST, GET"})
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS, GET"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return response, 200