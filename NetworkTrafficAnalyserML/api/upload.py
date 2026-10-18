from flask import Blueprint, request, jsonify
import os

upload_bp = Blueprint("upload", __name__)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@upload_bp.route("/api/upload", methods=["POST"])
def upload_pcap():
    file = request.files["pcap"]
    path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(path)
    return jsonify({"path": path})
