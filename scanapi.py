from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS from flask_cors
import requests

app = Flask(__name__)
CORS(app)

# Define a list of security headers to check
security_headers = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
]

# Function to check for security headers in a given URL
def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        results = {}
        for header in security_headers:
            results[header] = "Safe" if header in headers else "Missing"

        # Classify severity based on the header
        high_severity = [header for header, result in results.items() if header == "Strict-Transport-Security" and result == "Missing"]
        medium_severity = [header for header, result in results.items() if header == "Content-Security-Policy" and result == "Missing"]
        low_severity = [header for header, result in results.items() if header != "Strict-Transport-Security" and header != "Content-Security-Policy" and result == "Missing"]

        severity = {}
        if high_severity:
            severity["High Severity"] = high_severity
        if medium_severity:
            severity["Medium Severity"] = medium_severity
        if low_severity:
            severity["Low Severity"] = low_severity

        results["Security Headers"] = severity
        return results

    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {e}"}

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    try:
        payload = "1' OR '1'='1"
        response = requests.get(url + f"?id={payload}")
        
        if "error" in response.text.lower():
            return {"SQL Injection": "Detected"}
        else:
            return {"SQL Injection": "Not Detected"}

    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {e}"}

# Function to check for Cross-Site Scripting (XSS) vulnerability
def check_xss(url):
    try:
        payload = "<script>alert('XSS');</script>"
        response = requests.get(url + f"?q={payload}")
        
        if payload in response.text:
            return {"XSS": "Detected"}
        else:
            return {"XSS": "Not Detected"}

    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {e}"}

# Function to check for Directory Traversal vulnerability
def check_directory_traversal(url):
    try:
        payload = "../"
        response = requests.get(url + f"?path={payload}")
        
        if "Permission denied" in response.text:
            return {"Directory Traversal": "Detected"}
        else:
            return {"Directory Traversal": "Not Detected"}

    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {e}"}

# Function to check if a website is hosted on Shopify
def is_shopify_website(url):
    try:
        response = requests.get(url)
        if "shopify-checkout" in response.text:
            return {"Shopify Hosting": "Detected"}
        else:
            return {"Shopify Hosting": "Not Detected"}
    except requests.exceptions.RequestException:
        return {"Shopify Hosting": "Not Detected"}

# Function to check for potential DDoS vulnerability
def check_ddos_vulnerability(url):
    try:
        response = requests.get(url)
        if len(response.text) > 100000:  # Adjust the threshold as needed
            return {"DDoS Vulnerability": "Potential"}
        else:
            return {"DDoS Vulnerability": "Not Detected"}
    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {e}"}

# Combine all vulnerability checks
def scan_all_vulnerabilities(url):
    results = {
        "Security Headers": check_security_headers(url),
        "SQL Injection": check_sql_injection(url),
        "XSS": check_xss(url),
        "Directory Traversal": check_directory_traversal(url),
        "Shopify Hosting": is_shopify_website(url),
        "DDoS Vulnerability": check_ddos_vulnerability(url)
    }
    return results

@app.route('/scan_all_vulnerabilities', methods=['GET'])
def scan_all_vulnerabilities_api():
    website_url = request.args.get('url')
    result = scan_all_vulnerabilities(website_url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
