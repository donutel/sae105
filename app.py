from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor
import os
import re
from collections import Counter
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pcap'}

# Thread pool for async processing
executor = ThreadPoolExecutor()

# Helper function: Check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper function: Parse file content
def parse_file(file_path):
    protocols = {"SSH": 0, "HTTP": 0, "DNS": 0, "Others": 0}
    ip_data = Counter()
    packet_sizes = []
    errors = 0
    timestamps = []

    try:
        with open(file_path, 'r') as f:
            for line in f:
                # Parse protocols
                if "ssh" in line:
                    protocols["SSH"] += 1
                elif "http" in line:
                    protocols["HTTP"] += 1
                elif "PTR" in line or "NXDomain" in line:
                    protocols["DNS"] += 1
                else:
                    protocols["Others"] += 1
                
                # Extract IP addresses
                match = re.search(r"IP\s+([^\s]+)\s+>\s+([^\s]+):", line)
                if match:
                    src_ip, dest_ip = match.groups()
                    ip_data[src_ip] += 1
                    ip_data[dest_ip] += 1

                # Extract packet sizes
                match_size = re.search(r"length\s+(\d+)", line)
                if match_size:
                    packet_sizes.append(int(match_size.group(1)))

                # Count errors
                if "RST" in line or "error" in line.lower():
                    errors += 1

                # Extract timestamps
                match_timestamp = re.search(r"(\d{2}:\d{2}:\d{2}\.\d+)", line)
                if match_timestamp:
                    timestamps.append(match_timestamp.group(1))
    except Exception as e:
        return {"error": f"Error parsing file: {str(e)}"}

    # Calculate additional metrics
    total_packets = len(packet_sizes)
    avg_packet_size = sum(packet_sizes) / total_packets if total_packets > 0 else 0

    return {
        "protocols": protocols,
        "ip_data": dict(ip_data.most_common(10)),  # Top 10 IPs
        "packet_sizes": packet_sizes,
        "errors": errors,
        "timestamps": timestamps,
        "total_packets": total_packets,
        "avg_packet_size": avg_packet_size,
    }

# Route: Home page
@app.route('/')
def index():
    return render_template('upload.html')

# Route: Handle file upload
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Process the file asynchronously
        future = executor.submit(parse_file, file_path)
        analysis = future.result()  # Wait for the result

        if "error" in analysis:
            return jsonify({"error": analysis["error"]}), 500

        return jsonify(analysis)

    return jsonify({"error": "Invalid file type"}), 400

# Route: Analyze results (optional caching)
@app.route('/results/<filename>')
def results(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    analysis = parse_file(file_path)
    if "error" in analysis:
        return jsonify({"error": analysis["error"]}), 500

    return jsonify(analysis)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
