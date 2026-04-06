"""
Flask Application Entry Point for Cloud Scanner Dashboard
"""

from flask import Flask, jsonify
from flask_cors import CORS
from cloud_scanner.core.config import Config
from cloud_scanner.dashboard.api import api_bp
import os

def create_app(test_config=None):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    
    # Enable CORS for all routes (for development)
    CORS(app)
    
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=Config.get_db_path(),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Register Blueprints
    app.register_blueprint(api_bp, url_prefix='/api')

    @app.route('/health')
    def health_check():
        return jsonify({'status': 'healthy', 'app': Config.APP_NAME, 'version': Config.VERSION})

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
