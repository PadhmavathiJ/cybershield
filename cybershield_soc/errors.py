from flask import jsonify, render_template
from werkzeug.exceptions import HTTPException

def register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden(e):
        return _error_response(403, "You are not allowed to perform this action.")

    @app.errorhandler(404)
    def not_found(e):
        return _error_response(404, "The requested resource was not found.")

    @app.errorhandler(422)
    def invalid_data(e):
        return _error_response(422, "The submitted data is invalid.")

    @app.errorhandler(503)
    def database_unavailable(e):
        return _error_response(503, "The service is temporarily unavailable.")

    @app.errorhandler(Exception)
    def unexpected_error(e):
        if isinstance(e, HTTPException):
            return _error_response(e.code or 500, e.description)
        app.logger.exception("Unhandled application error")
        return _error_response(500, "An unexpected error occurred.")

def _error_response(status, message):
    if status == 500:
        message = "An unexpected error occurred."
    response = jsonify({"error": message, "status": status})
    response.status_code = status
    return response