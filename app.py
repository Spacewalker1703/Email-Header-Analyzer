from flask import Flask, render_template, request, make_response, redirect, url_for
import re
import spf
import dkim
import geoip2.database
import dns.resolver
from email import message_from_string
from whois import whois
from weasyprint import HTML

app = Flask(__name__)

# Path to the GeoLite2-City.mmdb file
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    header = request.form.get('header')

    if not header:
        return "Please provide an email header!", 400

    # Perform analysis
    analysis_results = analyze_header(header)

    # Calculate final classification based on analysis
    analysis_results['Final Classification'] = classify_email(analysis_results)

    # Check if PDF report is requested
    if request.form.get('Generate Report'):
        return generate_pdf_report(analysis_results)

    # Render results page
    return render_template('results.html', results=analysis_results, header=header)

def generate_pdf_report(results):
    try:
        html_content = render_template('report_template.html', results=results)
        pdf = HTML(string=html_content).write_pdf()

        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=Email_Analysis_Report.pdf'
        return response
    except Exception as e:
        return f"PDF Generation Error: {str(e)}", 500

def analyze_header(header):
    results = {
        'SPF': 'Not Checked',
        'DKIM': 'Not Checked',
        'DMARC': 'Not Checked',
        'Extracted URLs': [],
        'URL Analysis': [],
        'Domain Reputation': 'Not Available',
        'IP Address': 'Not Found',
        'IP Geolocation': {'City': 'Not Found', 'Country': 'Not Found', 'Latitude': 'N/A', 'Longitude': 'N/A'},
        'Header Validation': 'Not Checked',
        'Attachment Analysis': 'Not Implemented',
    }
    score = 0  # Initialize the score for classification

    try:
        # SPF Validation
        spf_result = check_spf(header)
        results['SPF'] = spf_result if spf_result else 'SPF Check Failed'
        score += 1 if spf_result == "pass" else -1

        # DKIM Validation
        dkim_result = check_dkim(header)
        results['DKIM'] = dkim_result if dkim_result else 'DKIM Check Failed'
        score += 1 if "Valid" in dkim_result else -1

        # DMARC Validation
        dmarc_result = check_dmarc(header)
        results['DMARC'] = dmarc_result if dmarc_result else 'DMARC Record Not Found'

        # Extract and Analyze URLs
        urls = extract_urls(header)
        results['Extracted URLs'] = urls if urls else ['No URLs Found']

        url_analysis = analyze_urls(urls)
        results['URL Analysis'] = url_analysis if url_analysis else ['No Analysis Available']

        # Domain Reputation Check
        sender_domain = extract_domain(header)
        if sender_domain:
            domain_reputation = check_domain_reputation(sender_domain)
            results['Domain Reputation'] = domain_reputation

        # IP Geolocation
        ip_address = extract_ip(header)
        if ip_address:
            results['IP Address'] = ip_address
            ip_location = get_ip_location(ip_address)
            results['IP Geolocation'] = ip_location if ip_location else results['IP Geolocation']

    except Exception as e:
        results['Error'] = f"An error occurred during analysis: {str(e)}"

    results['Score'] = score  # Add score for classification
    return results

def classify_email(results):
    score = results.get('Score', 0)
    if score <= -2:
        return "This seems to be a malicious email."
    elif -1 <= score <= 1:
        return "This email appears to be suspicious."
    else:
        return "This seems to be a legitimate email."

# Helper Functions

def extract_ip(header):
    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
    return match.group(0) if match else None

def check_spf(header):
    try:
        ip_address = extract_ip(header)
        sender_domain = extract_domain(header)
        if not ip_address or not sender_domain:
            return "SPF Check Failed: Missing IP or Domain"
        result, explanation = spf.check2(ip_address, sender_domain)
        return result
    except Exception as e:
        return f"SPF Check Error: {str(e)}"

def check_dkim(header):
    try:
        dkim_result = dkim.verify(header.encode('utf-8'))
        return "Valid" if dkim_result else "Invalid"
    except Exception as e:
        return f"DKIM Check Error: {str(e)}"

def check_dmarc(header):
    try:
        domain = extract_domain(header)
        dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for txt_record in dmarc_record:
            if 'v=DMARC1' in txt_record.to_text():
                return txt_record.to_text().strip('"')
        return "No DMARC record found"
    except Exception as e:
        return f"DMARC Check Error: {str(e)}"

def extract_domain(header):
    match = re.search(r'@([\w.-]+)', header)
    return match.group(1) if match else None

def get_ip_location(ip_address):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)
            return {
                'City': response.city.name or "Unknown",
                'Country': response.country.name or "Unknown",
                'Latitude': response.location.latitude or "N/A",
                'Longitude': response.location.longitude or "N/A"
            }
    except Exception as e:
        return {"Error": f"GeoIP Lookup Error: {str(e)}"}

def extract_urls(header):
    url_pattern = re.compile(r'(https?://[^\s]+)', re.IGNORECASE)
    urls = re.findall(url_pattern, header)
    return urls if urls else []

def analyze_urls(urls):
    return [f"{url} - No threat detected" for url in urls] if urls else ["No Analysis Available"]

def check_domain_reputation(domain):
    try:
        whois_result = whois(domain)
        return {
            "Domain": domain,
            "Registrar": whois_result.registrar or "Unknown"
        }
    except Exception as e:
        return {"Error": f"Domain Reputation Check Error: {str(e)}"}

if __name__ == '__main__':
    app.run(debug=True)
