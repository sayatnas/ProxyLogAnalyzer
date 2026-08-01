from flask import Flask
from flask import jsonify
from datetime import datetime
app = Flask(__name__)



@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response


@app.route('/api/hello')
def index():
    return jsonify({'message': 'Hello, World!', 'time': datetime.now().isoformat()})
#
if __name__ == '__main__':
    app.run(port=5000, debug=True)
