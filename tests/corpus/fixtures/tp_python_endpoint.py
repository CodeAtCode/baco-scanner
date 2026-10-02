# TRUE POSITIVE: unprotected Python endpoint
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/delete_user', methods=['POST'])
def delete_user():
    user_id = request.form.get('user_id')
    # No authentication or authorization check
    db.execute(f"DELETE FROM users WHERE id = {user_id}")
    return jsonify({'deleted': user_id})