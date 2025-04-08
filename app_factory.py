import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
# from flask_cors import CORS

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    # 設定の読み込み（環境変数やファイルからの設定など）
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///docu_mentor.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'static/uploads'
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

    # Celery 用の設定
    app.config['CELERY_BROKER_URL'] = os.getenv("REDIS_URL", "redis://localhost:6380/0")
    app.config['CELERY_RESULT_BACKEND'] = app.config['CELERY_BROKER_URL']

    # PDFKit 設定（必要なら）
    app.config['WKHTMLTOPDF_PATH'] = os.getenv("WKHTMLTOPDF_PATH", "C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    
    # Cross-Origin Resource Sharing が必要であれば
    # from flask_cors import CORS
    # CORS(app)

    # 拡張機能の初期化
    db.init_app(app)
    login_manager.init_app(app)

    return app
