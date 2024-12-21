from flask import Flask, render_template, jsonify, request
import requests
import mysql.connector
from datetime import datetime, timedelta  

app = Flask(__name__)

# Database connection 
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='toor',
        database='cyber_security_db'
    )

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/cves/list', methods=['GET'])
def cves_list():
    filter_type = request.args.get('filterType')
    filter_value = request.args.get('filterValue')
    
    query = "SELECT * FROM vulnerabilities"
    params = []

    if filter_type == "year":
        query += " WHERE YEAR(published_date) = %s"
        params.append(filter_value)
    elif filter_type == "score":
        min_score, max_score = map(float, filter_value.split('-'))
        query += " WHERE baseScore BETWEEN %s AND %s"
        params.extend([min_score, max_score])
    elif filter_type == "lastModified":
        days_ago = datetime.now() - timedelta(days=int(filter_value))
        query += " WHERE last_modified >= %s"
        params.append(days_ago)

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, tuple(params))
        cve_data = cursor.fetchall()
    except Exception as e:
        print("Error fetching data:", e)
        cve_data = []
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('cves_list.html', cve_data=cve_data)


@app.route('/fetch-and-store', methods=['GET'])
def fetch_and_store_data():
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 100
    start_index = 0  # Starting index for API pagination
    total_results = None  # To be determined from the first API response

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print("DB Connected")

        while True:
            # Fetch data from the API in batches
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            response = requests.get(api_url, params=params)
            if response.status_code != 200:
                print("Error fetching data from API:", response.status_code)
                return jsonify({"error": "Failed to fetch data from the API"}), 500

            data = response.json()

            # Set total_results from the first API response
            if total_results is None:
                total_results = data.get('totalResults', 0)

            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                break

            # Process each batch of vulnerabilities
            batch_data = []
            for item in vulnerabilities:
                cve_item = item.get('cve', {})
                if not cve_item:
                    continue

                # Extract data
                item_id = cve_item.get('id', None)
                source_identifier = cve_item.get('sourceIdentifier', None)
                published_date = cve_item.get('published', None)
                modified_date = cve_item.get('lastModified', None)
                vuln_status = cve_item.get('vulnStatus', None)

                # Extract CVSS metrics
                metrics = cve_item.get('metrics', {})
                cvss_v2 = metrics.get('cvssMetricV2', [])
                cvss_data = cvss_v2[0].get('cvssData', {}) if cvss_v2 else {}

                cvss_version = cvss_data.get('version', None)
                base_score = cvss_data.get('baseScore', None)
                access_vector = cvss_data.get('accessVector', None)
                access_complexity = cvss_data.get('accessComplexity', None)
                authentication = cvss_data.get('authentication', None)
                base_severity = cvss_v2[0].get('baseSeverity', None) if cvss_v2 else None
                exploitability_score = cvss_v2[0].get('exploitabilityScore', None) if cvss_v2 else None

                # Convert date strings to datetime objects
                published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f') if published_date else None
                modified_date = datetime.strptime(modified_date, '%Y-%m-%dT%H:%M:%S.%f') if modified_date else None

                # Append data to batch
                batch_data.append((
                    item_id, source_identifier, published_date, modified_date, vuln_status,
                    cvss_version, base_score, access_vector, access_complexity,
                    authentication, base_severity, exploitability_score
                ))

            # Insert batch into the database
            query = """
                INSERT INTO vulnerabilities (
                    id, identifier, published_date, last_modified, status,
                    cvss_version, baseScore, accessVector, access_complexity,
                    authentication, base_severity, exploitability_score
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    identifier=VALUES(identifier), 
                    published_date=VALUES(published_date),
                    last_modified=VALUES(last_modified),
                    status=VALUES(status),
                    cvss_version=VALUES(cvss_version),
                    baseScore=VALUES(baseScore),
                    accessVector=VALUES(accessVector),
                    access_complexity=VALUES(access_complexity),
                    authentication=VALUES(authentication),
                    base_severity=VALUES(base_severity),
                    exploitability_score=VALUES(exploitability_score)
            """
            cursor.executemany(query, batch_data)
            conn.commit()

            # Update the start index for the next batch
            start_index += results_per_page

            # Break the loop if all results are fetched
            if start_index >= total_results:
                break

        print("Data fetched and stored successfully in batches.")
        return jsonify({"message": "Data fetched and stored successfully!"}), 200

    except Exception as e:
        print("Error occurred:", e)
        return jsonify({"error": str(e)}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()




@app.route('/cves/list/<id>')
def each_cve(id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # to get the record CVE ID wise 
        query = "SELECT * FROM vulnerabilities WHERE id = %s"
        cursor.execute(query, (id,))
        cve_data = cursor.fetchone()
        if cve_data:
            return render_template('each_cves.html', cve_data=cve_data)
        else:
            return jsonify({"error": "CVE not found"}), 404



# 1. Filter by CVE ID
@app.route('/api/cves/by-id', methods=['GET'])
def get_cve_by_id():
    cve_id = request.args.get('cve_id')
    if not cve_id:
        return jsonify({"error": "CVE ID is required"}), 400
 
    query = "SELECT * FROM vulnerabilities WHERE id = %s"
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, (cve_id,))
        result = cursor.fetchall()
        if not result:
            return jsonify({"error": "CVE not found"}), 404
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
 
# 2. Filter by CVE ID belonging to a specific year
@app.route('/api/cves/by-year', methods=['GET'])
def get_cves_by_year():
    year = request.args.get('year')
    if not year or not year.isdigit():
        return jsonify({"error": "Valid year is required"}), 400
 
    query = """
        SELECT * FROM vulnerabilities 
        WHERE YEAR(published_date) = %s
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, (year,))
        result = cursor.fetchall()
        if not result:
            return jsonify({"error": "No CVEs found for the specified year"}), 404
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
 
# 4. Filter by last modified in the past N days
@app.route('/api/cves/last-modified', methods=['GET'])
def get_cves_last_modified():
    days = request.args.get('days')
    if not days or not days.isdigit():
        return jsonify({"error": "Number of days must be provided and be a valid integer"}), 400
 
    days_ago = datetime.now() - timedelta(days=int(days))  # Make sure timedelta is imported
    query = """
        SELECT * FROM vulnerabilities 
        WHERE last_modified >= %s
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, (days_ago,))
        result = cursor.fetchall()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)