"""
app.py – Flask application factory for SecureAuth.
"""

import os
import sys
import logging
from dotenv import load_dotenv

# ── Load environment ──────────────────────────────────────────────
_backend_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.dirname(_backend_dir)
load_dotenv(dotenv_path=os.path.join(_project_dir, 'config', '.env'))

# ── Logging ───────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s [%(levelname)s] %(name)s – %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

# ── Add backend dir to path ───────────────────────────────────────
sys.path.insert(0, _backend_dir)

from flask      import Flask, jsonify, send_from_directory
from flask_cors import CORS

from database           import init_db, seed_demo_data
from routes.auth        import auth_bp
from routes.dashboard   import dash_bp
from security.protection import security_headers


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    # Config
    app.config['SECRET_KEY']   = os.getenv('SECRET_KEY', 'change-me')
    app.config['JSON_SORT_KEYS'] = False

    # CORS – allow frontend on any localhost port
    CORS(app, resources={r'/api/*': {
        'origins':  ['http://localhost:*', 'http://127.0.0.1:*', 'null', '*'],
        'methods':  ['GET', 'POST', 'OPTIONS'],
        'allow_headers': ['Content-Type', 'Authorization'],
    }}, supports_credentials=True)

    # ── Register blueprints ───────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(dash_bp)

    # ── Security headers on every response ───────────────────────
    app.after_request(security_headers)

    # ── Serve frontend static files ───────────────────────────────
    _frontend_dir = os.path.join(_project_dir, 'frontend')

    @app.route('/')
    def index():
        return send_from_directory(_frontend_dir, 'index.html')

    @app.route('/<path:filename>')
    def static_files(filename):
        return send_from_directory(_frontend_dir, filename)

    # ── Health check ──────────────────────────────────────────────
    @app.route('/health')
    def health():
        return jsonify({'status': 'ok', 'service': 'SecureAuth API'}), 200

    # ── Global error handlers ─────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Endpoint not found.'}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({'error': 'Method not allowed.'}), 405

    @app.errorhandler(500)
    def internal_error(e):
        logger.exception("Internal server error")
        return jsonify({'error': 'Internal server error.'}), 500

    return app


if __name__ == '__main__':
    # ── Initialize DB & seed demo data ───────────────────────────
    logger.info("Initializing database …")
    init_db()
    seed_demo_data()

    # ── Pre-load AI ensemble (trains if no cached models) ─────────
    logger.info("Loading AI ensemble …")
    from ai.ensemble_model import get_ensemble
    get_ensemble()   # This trains + caches models if needed

    # ── Start server ──────────────────────────────────────────────
    port  = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', '1') == '1'

    app = create_app()
    logger.info("🚀 SecureAuth starting on http://localhost:%d", port)
    app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)
