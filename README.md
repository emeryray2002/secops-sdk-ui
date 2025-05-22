# SecOps SDK UI

SecOps SDK UI is a web-based interface for Google Chronicle's Security Operations platform. This application provides a user-friendly dashboard to interact with the SecOps SDK, allowing security teams to:

- Search and investigate UDM events
- Work with threat intelligence data
- Manage detection rules
- Monitor alerts and cases
- Ingest and process log data
- Utilize Gemini AI capabilities for security operations

The application uses Google OAuth for authentication and can be deployed to Google Cloud App Engine for easy access by your security team.

# Deployment Guide

This document explains how to set up OAuth credentials in Google Cloud Platform and deploy the SecOps SDK UI application to App Engine.

## Prerequisites

- Google Cloud Platform account with billing enabled
- `gcloud` CLI tool installed and configured
- Python 3.9+ installed
- Access to the SecOps SDK

## Setting Up OAuth Credentials

1. **Create a Google Cloud Project** (or use an existing one):
   ```bash
   gcloud projects create [PROJECT_ID] --name="SecOps SDK UI"
   gcloud config set project [PROJECT_ID]
   ```

2. **Enable Required APIs**:
   ```bash
   gcloud services enable appengine.googleapis.com oauth2-http.googleapis.com
   ```

3. **Create OAuth Consent Screen**:
   - Go to [APIs & Services > OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent)
   - Choose User Type (Internal for organization use only, or External)
   - Fill in required information (App name, user support email, developer contact)
   - Add scopes: `.../auth/userinfo.email`, `.../auth/userinfo.profile`, `openid`, `.../auth/cloud-platform`
   - Add test users if using External user type

4. **Create OAuth Credentials**:
   - Go to [APIs & Services > Credentials](https://console.cloud.google.com/apis/credentials)
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Web application"
   - Set Name: "SecOps SDK UI"
   - Add Authorized JavaScript origins:
     - `https://[PROJECT_ID].appspot.com` (or your custom domain)
     - `http://localhost:8080` (for local testing)
   - Add Authorized redirect URIs:
     - `https://[PROJECT_ID].appspot.com/oauth2callback`
     - `http://localhost:8080/oauth2callback` (for local testing)
   - Copy the generated Client ID and Client Secret

## Configuration

1. **Create app.yaml File**:
   ```bash
   cp app.yaml.example app.yaml
   ```

2. **Edit app.yaml** with your environment variables:
   ```yaml
   runtime: python311
   entrypoint: gunicorn -b :$PORT app:app

   handlers:
   - url: /static
     static_dir: static
   - url: /.*
     script: auto

   automatic_scaling:
     min_idle_instances: 0
     max_idle_instances: 1
     min_pending_latency: 30ms
     max_pending_latency: automatic
     max_concurrent_requests: 50

   env_variables:
     GOOGLE_CLIENT_ID: "your-client-id.apps.googleusercontent.com"
     GOOGLE_CLIENT_SECRET: "your-client-secret"
     FLASK_SECRET_KEY: "a-secure-random-string-for-sessions"
     FLASK_APP_URL: "https://your-project-id.appspot.com"  # Important for OAuth redirect
   ```

3. **Create a .env file for local development** (optional):
   ```
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   FLASK_SECRET_KEY=a-secure-random-string
   FLASK_APP_URL=http://localhost:8080
   FLASK_DEBUG=True
   ```

## Deployment to App Engine

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Test locally** (optional):
   ```bash
   python app.py
   ```

3. **Deploy to App Engine**:
   ```bash
   gcloud app deploy
   ```

4. **Open the deployed application**:
   ```bash
   gcloud app browse
   ```

## Configuration Variables Explained

| Variable | Description | Example |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | OAuth client ID from GCP credentials | `123456789-abc123def456.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | OAuth client secret | `ABCdef123456_abcDEF789` |
| `FLASK_SECRET_KEY` | Secret key for Flask sessions | Generate a random string |
| `FLASK_APP_URL` | Base URL of the application | `https://your-project-id.appspot.com` |
| `FLASK_DEBUG` | Enable debug mode (local only) | `True` or `False` |

## Usage

1. Open the application URL
2. Log in with your Google account (must have access to the Chronicle/SecOps resources)
3. Configure environments in the UI with your Chronicle instance details:
   - **Display Name**: Name for your environment
   - **Customer ID**: Your Chronicle instance UUID
   - **GCP Project ID**: The GCP project ID containing the Chronicle instance
   - **Region**: Region of your Chronicle instance (e.g., `us`, `europe`)

## Troubleshooting

- If authentication fails, verify OAuth credentials and redirect URIs
- Check App Engine logs: `gcloud app logs tail`
- For permission issues, ensure the user has appropriate access to Chronicle resources
- For OAuth errors, verify that your app is properly configured in the OAuth consent screen 