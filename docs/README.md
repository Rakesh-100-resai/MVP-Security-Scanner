

# **Sentinel AI - MVP Security Scanner**

Sentinel AI is a containerized web service designed for automated threat analysis. It provides a simple RESTful API for submitting files and domains, which are then processed asynchronously by a worker to scan for malware, vulnerabilities, and misconfigurations.

## **Features**

  * **File Scanning**:
      * **Antivirus**: Scans files against a virus database using **ClamAV**.
      * **Custom Rule-Based Detection**: Matches files against custom **YARA** rules to find malware families, obfuscated code, or other suspicious patterns.
  * **Domain & URL Scanning**:
      * **SSL/TLS Analysis**: Checks for valid SSL certificates, expiry dates, and encryption ciphers.
      * **HTTP Header Analysis**: Inspects security headers (like `Content-Security-Policy`, `X-Frame-Options`) for common web application misconfigurations.
      * **Service Banner Scanning**: Probes common ports (FTP, SSH, etc.) to identify running services and their versions.
  * **Asynchronous Architecture**: Uses a **Redis** job queue to handle submissions, ensuring the API remains fast and responsive while workers perform time-consuming scans in the background.
  * **Scalable & Containerized**: The entire application stack is managed with **Docker Compose**, making it easy to set up, deploy, and scale.
  * **Object Storage**: Uses **MinIO** for scalable and reliable storage of submitted files.

-----

## **Architecture**

The system follows a decoupled, asynchronous architecture to efficiently handle analysis tasks.

1.  **API Server (FastAPI)**: The user interacts with this component. It handles authentication, validates requests, and submits jobs.
2.  **Redis (Job Queue)**: The API server pushes a job (e.g., `{"type": "file", "file_id": "..."}`) onto a Redis list which acts as a queue.
3.  **Worker (Python)**: This background process continuously listens for jobs on the Redis queue. When it receives a job, it performs the required scans.
4.  **Data Stores**:
      * For file jobs, the worker fetches the file from **MinIO** object storage.
      * Once a scan is complete, the worker writes a detailed JSON report back to a **Redis** key (e.g., `report:{target_id}`).
5.  **User (Polling)**: The user polls the `GET /report/{target_id}` endpoint. The API fetches the corresponding report from Redis and returns it.

-----

## **Technology Stack**

  * **Backend API**: Python, FastAPI
  * **Worker**: Python
  * **Job Queue & Cache**: Redis
  * **File Storage**: MinIO (S3-compatible object storage)
  * **Scanning Engines**: ClamAV, YARA
  * **Containerization**: Docker & Docker Compose

-----

## **🔧 Setup and Installation**

#### **Prerequisites**

  * Docker
  * Docker Compose

#### **Installation Steps**

1.  **Clone the Repository**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```
2.  **Configure Environment Variables**
    Create a `.env` file in the project root. You can copy the provided `.env.example` file if one exists. This file will contain all the necessary configuration for the services.
    ```env
    # For API and Worker
    REDIS_HOST=redis
    MINIO_HOST=minio:9000
    CLAMAV_HOST=clamav

    # For API
    SECRET_KEY=a_very_secret_key_for_jwt
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD=admin123

    # For MinIO
    MINIO_ROOT_USER=minioadmin
    MINIO_ROOT_PASSWORD=minioadmin
    ```
3.  **Add YARA Rules**
    Create a directory named `rules` in your project root and place your `.yar` or `.yara` files inside it. The worker will automatically load all rules from this directory.
4.  **Build and Run the Services**
    Use Docker Compose to build the images and start all the containers in detached mode.
    ```bash
    docker-compose build
    docker-compose up -d
    ```
    The services will now be running in the background.

-----

## **📝 API Usage**

All requests require a Bearer token for authorization.

#### **1. Obtain Authentication Token**

First, get a JWT token by providing the admin credentials.

  * **Endpoint**: `POST /token`
  * **Request (`curl`)**:
    ```bash
    curl -X 'POST' \
      'http://localhost:8000/token' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'username=admin&password=admin123'
    ```
  * **Successful Response**:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1Ni...",
      "token_type": "bearer"
    }
    ```

#### **2. Submit a File for Scanning**

Upload a file using `multipart/form-data`.

  * **Endpoint**: `POST /upload`
  * **Request (`curl`)**:
    ```bash
    curl -X 'POST' \
      'http://localhost:8000/upload' \
      -H 'Authorization: Bearer <YOUR_ACCESS_TOKEN>' \
      -F 'file=@/path/to/your/test_doc.txt'
    ```
  * **Successful Response**:
    ```json
    {
      "file_id": "a6033d30-a99c-4715-8a0d-c27fe43548fa",
      "message": "File submitted for scanning"
    }
    ```

#### **3. Submit a URL/Domain for Scanning**

Submit a URL for SSL, header, and banner analysis.

  * **Endpoint**: `POST /submit_url`
  * **Request (`curl`)**:
    ```bash
    curl -X 'POST' \
      'http://localhost:8000/submit_url' \
      -H 'Authorization: Bearer <YOUR_ACCESS_TOKEN>' \
      -H 'Content-Type: application/json' \
      -d '{"url": "https://ifocussystec.com"}'
    ```
  * **Successful Response**:
    ```json
    {
      "job_id": "8d3d194b-a4ff-452e-a96a-d564f6270233",
      "domain": "ifocussystec.com",
      "message": "Domain submitted for SSL check"
    }
    ```

#### **4. Fetch a Scan Report**

Use the `file_id` or `job_id` from the submission response to retrieve the analysis report. It may take a few moments for the worker to process the job.

  * **Endpoint**: `GET /report/{target}`
  * **Request (`curl`)**:
    ```bash
    curl -X 'GET' \
      'http://localhost:8000/report/8d3d194b-a4ff-452e-a96a-d564f6270233' \
      -H 'Authorization: Bearer <YOUR_ACCESS_TOKEN>'
    ```
  * **Pending Response**:
    ```json
    {
      "target": "8d3d194b-a4ff-452e-a96a-d564f6270233",
      "status": "pending",
      "message": "Report not found yet"
    }
    ```
  * **Completed Response (Domain Scan Example)**:
    ```json
    {
      "target": "8d3d194b-a4ff-452e-a96a-d564f6270233",
      "report": {
        "job_id": "8d3d194b-a4ff-452e-a96a-d564f6270233",
        "domain": "ifocussystec.com",
        "timestamp": "2025-09-02T12:57:45.105420",
        "scan_results": {
          "ssl_scan": { "...": "..." },
          "header_analysis": { "...": "..." },
          "banner_scan": { "...": "..." }
        }
      },
      "message": "Report retrieved successfully"
    }
    ```

-----

## **Troubleshooting**

  * **Reports are always "pending"**: This means the worker is not completing its jobs. Check the worker's logs for errors.
    ```bash
    docker-compose logs -f worker
    ```
  * **Jobs are stuck in the queue**: You can check the number of jobs in the Redis queue. If the number is high and not decreasing, the worker has likely crashed.
    ```bash
    docker-compose exec redis redis-cli LLEN jobs
    ```
