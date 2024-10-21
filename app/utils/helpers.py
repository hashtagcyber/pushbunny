from flask import jsonify

def json_response(data, status=200):
    response = jsonify(data)
    response.status_code = status
    response.headers['Content-Type'] = 'application/json'
    return response

