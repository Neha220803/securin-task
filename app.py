from flask import Flask, render_template, jsonify, request  # Added 'request' here
import requests
import mysql.connector
from datetime import datetime, timedelta  # Added 'timedelta'

app = Flask(__name__)

# Database connection function
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='toor',
        database='cyber_security_db'
    )

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# CVE list route to display data on the HTML page
@app.route('/cves/list')
def cves_list():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Fetch data from the MySQL database
        cursor.execute("SELECT * FROM vulnerabilities")
        cve_data = cursor.fetchall()

        return render_template('cves_list.html', cve_data=cve_data)
    except Exception as e:
        print("Error occurred while fetching data:", e)
        return jsonify({"error": "Failed to fetch CVE data"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Route to fetch and store data from the NVD API into MySQL
@app.route('/fetch-and-store', methods=['GET'])
def fetch_and_store_data():
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if conn.is_connected():
            print("Connected to MySQL database")

        # Fetch data from the third-party API
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            print("Data fetched successfully.")

            if isinstance(data, dict) and 'vulnerabilities' in data:
                for item in data['vulnerabilities']:
                    cve_item = item.get('cve', {})
                    if not cve_item:
                        continue  # Skip invalid entries

                    # Extract data
                    item_id = cve_item.get('id', None)
                    source_identifier = cve_item.get('sourceIdentifier', None)
                    published_date = cve_item.get('published', None)
                    modified_date = cve_item.get('lastModified', None)
                    vuln_status = cve_item.get('vulnStatus', None)

                    # Extract CVSS metrics (optional)
                    metrics = cve_item.get('metrics', {})
                    cvss_v2 = metrics.get('cvssMetricV2', [])

                    # Initialize default values
                    cvss_version = None
                    base_score = None
                    access_vector = None
                    access_complexity = None
                    authentication = None
                    base_severity = None
                    exploitability_score = None

                    if cvss_v2:  # Check if cvssMetricV2 exists and is non-empty
                        cvss_data = cvss_v2[0].get('cvssData', {})
                        cvss_version = cvss_data.get('version', None)
                        base_score = cvss_data.get('baseScore', None)
                        access_vector = cvss_data.get('accessVector', None)
                        access_complexity = cvss_data.get('accessComplexity', None)
                        authentication = cvss_data.get('authentication', None)
                        base_severity = cvss_v2[0].get('baseSeverity', None)
                        exploitability_score = cvss_v2[0].get('exploitabilityScore', None)

                    # Convert date strings to datetime objects
                    published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f') if published_date else None
                    modified_date = datetime.strptime(modified_date, '%Y-%m-%dT%H:%M:%S.%f') if modified_date else None

                    # Insert data into the database
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
                    cursor.execute(query, (
                        item_id, source_identifier, published_date, modified_date, vuln_status,
                        cvss_version, base_score, access_vector, access_complexity,
                        authentication, base_severity, exploitability_score
                    ))

            conn.commit()
            print("Data inserted into the database.")
            return jsonify({"message": "Data fetched and stored successfully!"}), 200
        else:
            print("Failed to fetch data from API:", response.status_code)
            return jsonify({"error": "Failed to fetch data from the third-party API"}), 500

    except Exception as e:
        print("Error occurred:", e)
        return jsonify({"error": str(e)}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


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

# 3. Filter by CVE Score
@app.route('/api/cves/by-score', methods=['GET'])
def get_cves_by_score():
    min_score = request.args.get('min_score', 0)
    max_score = request.args.get('max_score', 10)
 
    if not min_score.isdigit() or not max_score.isdigit():
        return jsonify({"error": "Min and max scores must be numeric values"}), 400
 
    query = """
        SELECT * FROM vulnerabilities 
        WHERE baseScore BETWEEN %s AND %s
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, (min_score, max_score))
        result = cursor.fetchall()
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