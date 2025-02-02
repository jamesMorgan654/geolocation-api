# Geolocation API
This code is designed to work with a Cloud Run instance to create an API that you can use to send an IP address and it will return an object with relevant GEO information.  It also handles the updating of the MaxMind geolocation database used, which is stored in BigQuery.

## Why would you want this?
Analytics tools such as Google Analytics give you detailed location data down to the city level. However, for small businesses that operate in a tighter radius, such as town/suburb this is not detailed enough for them to understand whether their advertising is attracting the right customers.  This API can be used to further enhance this analytics giving them data down to the postcode level.  The key use case being to create a custom event parameter that is the town/suburb that the user was in when they visited the website. 

# Getting Started
1. **Setting up Google Secrets**

This application is designed to have the MAXMIND credentials stored in Google Secret Manager.  Set up a secret called "geolocation-webhook" and enter the following:
API_KEY={This is your API key to access the webhook}
MAXMIND_ACCOUNT_ID={Your Maxmind account id}
MAXMIND_LICENSE_KEY={Your Maxmind license key}

2. **Setting up Google Cloud Storage (GCS) Bucket**

This application uses GCS to save the memory of the webhook server.  Create a GCS bucket called "geolocation-webhook"
Optional: Set data expiration to automatically delete data older than 7 days.

3. **Setting Up BigQuery**

Create a BigQuery DataSet called geodata for the application to push to. The data is quite large so this speeds up the process of extracting it.  It also means you don't need much memory in your webhook server.

4. **Upload postcodes.csv To BigQuery**

In the repo there is a file called postcodes.csv.  Upload this to the bigquery dataset as a table called "postcodes".  
**Note that this only contains NZ postcodes.  You will need to update this if you are wanting this to work in another country.** 

4. **Deploy the application**

[![Deploy to Google Cloud Run](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run/?git_repo=https://github.com/jamesMorgan654/geolocation_api)

## Using the CLI
1. Clone/Fork the Git Repo and make any adjustments you want.
2. Deploy to GCP. NOTE: Make any changes to envs.
```bash
gcloud builds submit --tag gcr.io/$(gcloud config get-value project)/geolocation-api
gcloud run deploy geolocation-api --image gcr.io/$(gcloud config get-value project)/geolocation-api --platform managed --region us-central1 --allow-unauthenticated --port 8080 --memory 256Mi --cpu 0.25
```

5. **Refreshing the Database**
Create a google cloud trigger that makes a post request (with auth header) every day or so.  This would be the /update path of the API.