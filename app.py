from flask import Flask, render_template, jsonify, redirect, url_for
import requests 
import mysql.connector 
import json
from datetime import datetime

app = Flask(__name__)

# Database connection function
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='toor',  # Update with your MySQL password
        database='cyber_security_db'
    )

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# CVE list route to display data on the HTML page
@app.route('/cves/list')
def cves_list():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM vulnerabilities")
    cve_data = cursor.fetchall()
    cursor.close()
    conn.close()

    # Render data in the HTML page
    return render_template('cves_list.html', cve_data=cve_data)

# Route to fetch and store data from the NVD API into MySQL
@app.route('/fetch-and-store', methods=['GET'])
def fetch_and_store_data():
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    conn = None
    cursor = None
    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()
        if conn.is_connected():
            print("Connected to MySQL database")

        # Fetching data from the third-party API
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            print("Data fetched successfully.")
            if isinstance(data, dict) and 'vulnerabilities' in data:
                for item in data['vulnerabilities']:
                    cve_item = item.get('cve', {})
                    if not cve_item:
                        continue  # Skip 
                    # data from the API response
                    item_id = cve_item.get('id', None)  # CVE ID
                    source_identifier = cve_item.get('sourceIdentifier', None)
                    # description = cve_item.get('descriptions', [{}])[0].get('value', '')
                    published_date = cve_item.get('published', None)
                    modified_date = cve_item.get('lastModified', None)
                    vuln_status = cve_item.get('vulnStatus', None)
                    #  strings to datetime objects
                    published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f') if published_date else None
                    modified_date = datetime.strptime(modified_date, '%Y-%m-%dT%H:%M:%S.%f') if modified_date else None



                    # for 2nd table:
                    cve_item2=item.get('metrics',{})
                    # Extract CVSS metrics (optional)
                    # cvss_metrics = cve_item.get('metrics', {}).get('cvssMetricV2', {}).get[0]('cvssData', {})
                    cvss_version = cve_item['metrics']['cvssMetricV2'][0]['cvssData']['version']
                    baseScore = cve_item['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    accessVector =  cve_item['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                    access_complexity = cve_item['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                    authentication = cve_item['metrics']['cvssMetricV2'][0]['cvssData']['authentication']
                    base_severity = cve_item['metrics']['cvssMetricV2'][0]['baseSeverity'] 
                    exploitability_score = cve_item['metrics']['cvssMetricV2'][0]['exploitabilityScore']

                    # cvss_version  =cve_item['metrics']['cvssMetricV2']['cvssData']['version']

                    # SQL query to insert the data without duplicate
                    query = """
                        INSERT INTO vulnerabilities (
                            id, identifier, published_date, last_modified, status,
                            cvss_version, baseScore, accessVector, access_complexity,
                            authentication, base_severity, exploitability_score
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    
                    
                        
                    """

                    cursor.execute(query, (
                        item_id, source_identifier, published_date, modified_date, vuln_status,
                        cvss_version, baseScore, accessVector, access_complexity,
                        authentication, base_severity, exploitability_score
                    ))

            conn.commit()
            print("Data inserted into the database.")
            return jsonify({"message": "Data fetched and stored successfully!"}), 200
        else:
            print("Failed to fetch data from API:", response.status_code)
            return jsonify({"error": "Failed to fetch data from third-party API"}), 500

    except Exception as e:
        print("Error occurred:", e)
        return jsonify({"error": str(e)}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Route to display individual CVE details
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



# Filter by CVE ID belonging to a specific year
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



# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)