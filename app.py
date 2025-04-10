    import os
    import base64
    import json
    import random
    import string
    from io import BytesIO
    from datetime import datetime, timedelta
    from functools import wraps
    from celery import Celery
    #from app import db, Video
    from tasks import transcribe_video_task

    from flask import Flask, request, jsonify, make_response, render_template, abort, g, redirect, send_from_directory
    from flask_sqlalchemy import SQLAlchemy
    from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
    from PIL import Image
    from celery_app import celery
    import pytesseract

    import os
    import cloudinary
    import cloudinary.uploader
    import pytz
    import pdfkit
    import openai
    import jwt
    import requests

    # dotenv読み込み
    from dotenv import load_dotenv
    load_dotenv()

    # LINE Messaging API 用（公式アカウント）
    LINE_CHANNEL_ACCESS_TOKEN = os.getenv('LINE_CHANNEL_ACCESS_TOKEN')
    LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET')
    if not LINE_CHANNEL_ACCESS_TOKEN or not LINE_CHANNEL_SECRET:
    raise ValueError("LINE_CHANNEL_ACCESS_TOKEN または LINE_CHANNEL_SECRET が設定されていません。")

    from linebot import LineBotApi, WebhookHandler
    from linebot.models import TextMessage, TextSendMessage, MessageEvent


    JST = pytz.timezone("Asia/Tokyo")

    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

    # PostgreSQLなどに接続する想定（Render用）
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///docu_mentor.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 一時フォルダとして使用（OCRなどに使う）
    app.config['UPLOAD_FOLDER'] = 'static/uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)




    app.config['CELERY_BROKER_URL'] = os.getenv("REDIS_URL", "redis://localhost:6380/0")
    app.config['CELERY_RESULT_BACKEND'] = app.config['CELERY_BROKER_URL']
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret')

    # Cloudinary初期化
    cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
    )

    app.config['OPENAI_API_KEY'] = os.getenv('OPENAI_API_KEY', 'your-openai-api-key')
    openai.api_key = app.config['OPENAI_API_KEY']
    conversation_states = {}

    # PDFKit設定
    wkhtmltopdf_path = os.getenv("WKHTMLTOPDF_PATH", "C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    pdfkit_config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path) if os.path.exists(wkhtmltopdf_path) else None

    db = SQLAlchemy(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login_route'

    ENV_USERS = {
    os.getenv('ADMIN_USERNAME', 'admin'): {
        "password": os.getenv('ADMIN_PASSWORD', 'admin123'),
        "role": "env"
    }
    }

    line_bot_api = LineBotApi(LINE_CHANNEL_ACCESS_TOKEN)
    line_handler = WebhookHandler(LINE_CHANNEL_SECRET)




    ###############################################################################
    # DBモデル
    ###############################################################################
    class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # env, admin, manager, user
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    language = db.Column(db.String(10), default="ja")
    line_id = db.Column(db.String(100), nullable=True)
    line_approved = db.Column(db.Boolean, default=False)
    line_request_time = db.Column(db.DateTime, nullable=True)
    line_display_name = db.Column(db.String(100), nullable=True)

    progress = db.relationship('Progress', backref='user', lazy=True)
    quiz_submissions = db.relationship('QuizSubmission', backref='user', lazy=True)
    logs = db.relationship('LogEntry', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    class Company(db.Model):
    __tablename__ = 'company'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)
    login_code = db.Column(db.String(8), unique=True, nullable=False)

    users = db.relationship('User', backref='company', lazy=True)
    videos = db.relationship('Video', backref='company', lazy=True)

    # ▼ 動画ファイルはCloudinaryで保存し、cloudinary_urlで管理
    class Video(db.Model):
    __tablename__ = 'video'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    cloudinary_url = db.Column(db.String(500), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=False)
    version = db.Column(db.Integer, default=1)
    whisper_text = db.Column(db.Text, nullable=True)
    summary_text = db.Column(db.Text, nullable=True)
    ocr_text = db.Column(db.Text, nullable=True)
    views = db.Column(db.Integer, default=0)
    is_temporary = db.Column(db.Boolean, default=False)

    steps = db.relationship('VideoStep', backref='video', lazy=True, cascade="all, delete-orphan")
    quizzes = db.relationship('Quiz', backref='video', lazy=True, cascade="all, delete-orphan")
    progress = db.relationship('Progress', backref='video', lazy=True)

    class VideoStep(db.Model):
    __tablename__ = 'video_step'
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    time_start = db.Column(db.Integer, default=0)
    time_end = db.Column(db.Integer, default=0)
    order = db.Column(db.Integer, default=0)

    attachments = db.relationship('StepAttachment', backref='step', lazy=True, cascade="all, delete-orphan")

    # ▼ ステップ添付画像もcloudinary_urlで管理
    class StepAttachment(db.Model):
    __tablename__ = 'step_attachment'
    id = db.Column(db.Integer, primary_key=True)
    step_id = db.Column(db.Integer, db.ForeignKey('video_step.id'), nullable=False)
    cloudinary_url = db.Column(db.String(500), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)

    class Quiz(db.Model):
    __tablename__ = 'quiz'
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    auto_quiz_text = db.Column(db.Text, nullable=True)

    questions = db.relationship('QuizQuestion', backref='quiz', lazy=True, cascade="all, delete-orphan")
    submissions = db.relationship('QuizSubmission', backref='quiz', lazy=True)

    class QuizQuestion(db.Model):
    __tablename__ = 'quiz_question'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)
    explanation = db.Column(db.Text, nullable=True)

    options = db.relationship('QuizOption', backref='question', lazy=True, cascade="all, delete-orphan")

    class QuizOption(db.Model):
    __tablename__ = 'quiz_option'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('quiz_question.id'), nullable=False)
    option_text = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, default=False)

    class QuizSubmission(db.Model):
    __tablename__ = 'quiz_submission'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    answers = db.relationship('QuizAnswer', backref='submission', lazy=True, cascade="all, delete-orphan")

    class QuizAnswer(db.Model):
    __tablename__ = 'quiz_answer'
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('quiz_submission.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('quiz_question.id'), nullable=False)
    answer_text = db.Column(db.Text, nullable=True)
    option_id = db.Column(db.Integer, db.ForeignKey('quiz_option.id'), nullable=True)
    is_correct = db.Column(db.Boolean, default=False)

    class Progress(db.Model):
    __tablename__ = 'progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    completion_percentage = db.Column(db.Float, default=0.0)
    last_watched = db.Column(db.DateTime, default=datetime.utcnow)

    class LogEntry(db.Model):
    __tablename__ = 'log_entry'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)

    class Template(db.Model):
    __tablename__ = 'template'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    class PlaybackLog(db.Model):
    __tablename__ = 'playback_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    playback_position = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # ▼ PDFや文書はcloudinary_urlで保持
    class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    cloudinary_url = db.Column(db.String(500), nullable=False)
    department = db.Column(db.String(100), default="")
    category = db.Column(db.String(100), nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    line_share_flag = db.Column(db.Boolean, default=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)

    class PDFViewLog(db.Model):
    __tablename__ = 'pdf_view_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=True)

    class SearchLog(db.Model):
    __tablename__ = 'search_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    keyword = db.Column(db.String(200), nullable=False)
    found_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_flag = db.Column(db.Boolean, default=False)

    @login_manager.user_loader
    def load_user(user_id):
    return User.query.get(int(user_id))

    @app.route('/force_create_tables')
    def force_create_tables():
    with app.app_context():
        db.create_all()
    return "Tables created!"




    def make_celery(app):
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND'],
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


    ###############################################################################
    # ユーティリティ
    ###############################################################################
    def generate_login_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def to_jst(dt_utc):
    try:
        if dt_utc is None:
            return None
        return dt_utc.replace(tzinfo=pytz.utc).astimezone(JST).strftime("%Y-%m-%d %H:%M")
    except Exception as e:
        print(f"[JST変換エラー] {e}")
        return None

    def get_request_data():
    if request.is_json:
        return request.get_json()
    return request.form

    def generate_jwt(user):
    payload = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    return token

    def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header:
            return jsonify({"error": "Authorization header is missing"}), 401
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            user = User.query.get(payload["user_id"])
            if not user:
                return jsonify({"error": "User not found"}), 404
            g.current_user = user
        except Exception as e:
            return jsonify({"error": f"Invalid token: {str(e)}"}), 401
        return f(*args, **kwargs)
    return decorated

    def generate_temp_pdf_token(doc_id):
    payload = {
        "doc_id": doc_id,
        "exp": datetime.utcnow() + timedelta(hours=12)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    return token

    def upload_to_cloudinary(file_stream, resource_type="auto", folder="documentor", public_id_prefix=None):
    try:
        if not public_id_prefix:
            public_id_prefix = datetime.utcnow().strftime("%Y%m%d%H%M%S")

        result = cloudinary.uploader.upload(
            file_stream,
            resource_type=resource_type,
            folder=folder,
            public_id=public_id_prefix,
            use_filename=True,
            unique_filename=True,
            overwrite=True
        )
        return result["secure_url"]
    except Exception as e:
        print(f"Cloudinary upload error: {e}")
        return None

    ###############################################################################
    # Whisper要約＋クイズ生成 (Cloudinaryファイルを一時DL→解析)
    ###############################################################################
    def process_video(video, generation_mode="manual"):
    try:
        # Whisper文字起こし（外部APIを叩く）
        whisper_api_url = os.getenv("WHISPER_API_URL", "http://localhost:8001/transcribe")
        response = requests.post(whisper_api_url, json={"video_url": video.cloudinary_url}, timeout=300)
        if response.status_code == 200:
            result = response.json()
            video.whisper_text = result.get("text", "文字起こしが空でした")
        else:
            video.whisper_text = f"Transcription failed: {response.text}"

    except Exception as e:
        video.whisper_text = f"Transcription failed: {str(e)}"

    # OCR結果を取得
    ocr_text = video.ocr_text if video.ocr_text else ""

    # GPT要約（省略せずこのまま続けてOK）
    try:
        if generation_mode == "minutes":
            prompt_header = "以下の動画書き起こしと画像OCR結果から、会議の議事録として、主要議題、決定事項、アクションアイテムを生成してください。"
        else:
            prompt_header = (
                "以下の動画書き起こしと画像OCR結果を元に、操作マニュアルを作成してください。\n"
                "各ステップを箇条書きで示し、見やすい改行とレイアウトを心がけてください。"
            )
        summary_prompt = (
            f"{prompt_header}\n\n"
            f"【音声書き起こし】\n{video.whisper_text}\n\n"
            f"【画像OCR結果】\n{ocr_text}\n\n要約:"
        )
        summary_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "あなたはプロのマニュアル作成者です。"},
                {"role": "user", "content": summary_prompt}
            ],
            temperature=0.5,
            max_tokens=300
        )
        video.summary_text = summary_response.choices[0].message.content.strip()
    except Exception as e:
        video.summary_text = f"Summary generation failed: {str(e)}"

    # GPTクイズ（以降そのままでOK）
    try:
        quiz_prompt = (
            "以下の資料内容から、3問以上の日本語クイズを作成してください。\n"
            "出力形式は、各問題を「質問文、4つの選択肢、正解番号、解説」とし、改行区切りで出力してください。\n\n"
            f"【資料内容】\n{video.summary_text}\n\nクイズ:"
        )
        quiz_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "あなたはプロの教材作成者です。"},
                {"role": "user", "content": quiz_prompt}
            ],
            temperature=0.7,
            max_tokens=800
        )
        auto_quiz_text = quiz_response.choices[0].message.content.strip()
        quiz = Quiz.query.filter_by(video_id=video.id).first()
        if not quiz:
            quiz = Quiz(video_id=video.id, title=f"Quiz for {video.title}")
            db.session.add(quiz)
        quiz.auto_quiz_text = auto_quiz_text
    except Exception as e:
        quiz = Quiz.query.filter_by(video_id=video.id).first()
        if not quiz:
            quiz = Quiz(video_id=video.id, title=f"Quiz for {video.title}")
            db.session.add(quiz)
        quiz.auto_quiz_text = f"Quiz generation failed: {str(e)}"

    db.session.commit()


    ###############################################################################
    # Favicon
    ###############################################################################
    @app.route('/favicon.ico')
    def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                                'favicon.ico', mimetype='image/vnd.microsoft.icon')

    ###############################################################################
    # LINE Webhook
    ###############################################################################
    @app.route('/webhook', methods=['POST'])
    def line_webhook():
    body = request.get_data(as_text=True)
    signature = request.headers.get('X-Line-Signature')
    try:
        line_handler.handle(body, signature)
    except Exception as e:
        print("Error handling webhook:", e)
        return jsonify({"error": str(e)}), 400
    return 'OK', 200

    @line_handler.add(MessageEvent, message=TextMessage)
    def handle_line_text(event):
    global conversation_states

    line_user_id = event.source.user_id
    text = event.message.text.strip()
    command_text = text.lower()

    user = User.query.filter_by(line_id=line_user_id).first()
    if not user:
        user = User(
            username=f"line_{line_user_id}",
            email=f"line_{line_user_id}@example.com",
            role='user',
            line_id=line_user_id,
            is_blocked=True
        )
        user.set_password("line_login_dummy")
        db.session.add(user)
        db.session.commit()

    # 1) まず初回登録チェック
    if not user.company_id or not user.department or not user.line_display_name:
        tokens = text.split()
        if len(tokens) >= 3:
            company_code = tokens[0]
            department = tokens[1]
            display_name = " ".join(tokens[2:])
            company = Company.query.filter_by(login_code=company_code).first()
            if company:
                user.company_id = company.id
                user.department = department
                user.line_display_name = display_name
                db.session.commit()

                reply_text = (
                    f"企業情報が登録されました。\n"
                    f"企業コード: {company.login_code}\n"
                    f"部署: {department}\n"
                    f"表示名: {display_name}"
                )
                line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_text))
                return
            else:
                line_bot_api.reply_message(
                    event.reply_token,
                    TextSendMessage(text=f"入力された企業コード '{company_code}' は無効です。\n例: ABC123 営業部 山田太郎")
                )
                return
        else:
            prompt_text = (
                "初回ご利用ありがとうございます。\n"
                "企業コード、部署、表示名をスペース区切りで送信してください。\n"
                "例: ABC123 営業部 山田太郎"
            )
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=prompt_text))
            return

    # 2) ブロック中判定
    allowed_commands_if_blocked = ["ステータス", "変更"]
    if user.is_blocked and command_text not in allowed_commands_if_blocked:
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(text="現在ブロック状態です。管理者にお問い合わせください。")
        )
        return

    # 3) コマンド判定
    # "ステータス"
    if command_text == "ステータス":
        if user.company_id and user.department:
            company = Company.query.get(user.company_id)
            if company:
                reply = (f"あなたの所属企業は【{company.name}】（企業コード: {company.login_code}）\n"
                            f"部署: {user.department}\n"
                            f"表示名: {user.line_display_name}")
            else:
                reply = "所属企業情報が不明です。"
        else:
            reply = "まだ所属企業が登録されていません。"

        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
        return

    # "変更"
    if command_text == "変更":
        conversation_states[line_user_id] = {"expected": "change_request"}
        prompt_text = ("所属企業変更を開始します。\n以下の形式で送信してください。\n例: ABC123 営業部 新しい表示名")
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=prompt_text))
        return

    # 4) 会話状態チェック
    state = conversation_states.get(line_user_id, {})
    if state.get("expected") == "change_request":
        tokens = text.split()
        if len(tokens) < 3:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text="入力が不十分です。例: ABC123 営業部 新しい表示名"))
            return
        company_code = tokens[0]
        department = tokens[1]
        new_display_name = " ".join(tokens[2:])
        company = Company.query.filter_by(login_code=company_code).first()
        if company:
            user.company_id = company.id
            user.department = department
            user.line_display_name = new_display_name
            db.session.commit()
            reply = (f"所属企業が変更されました。\n"
                        f"新しい企業: {company.name}（企業コード: {company.login_code}）\n"
                        f"部署: {department}\n"
                        f"表示名: {new_display_name}")
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
        else:
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=f"入力された企業コード '{company_code}' は存在しません。")
            )
        conversation_states.pop(line_user_id, None)
        return

    # "pdf"
    if command_text == "pdf" and not state:
        conversation_states[line_user_id] = {"expected": "pdf_option"}
        options_text = "PDFを選択してください:\n1. マニュアル\n2. 議事録\n3. 社内規定"
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=options_text))
        return

    elif state.get("expected") == "pdf_option":
        ...
        return
    elif state.get("expected") == "pdf_keyword":
        ...
        return

    # 5) 既定応答
    default_reply = (
        "PDF   登録されているPDFが共有されます\n"
        "ステータス   現在の登録内容が確認できます\n"
        "変更    現在の登録内容を変更できます"
    )
    line_bot_api.reply_message(event.reply_token, TextSendMessage(text=default_reply))

    # "変更"
    if text.lower() == "変更":
        conversation_states[line_user_id] = {"expected": "change_request"}
        prompt_text = ("所属企業変更を開始します。\n以下の形式で送信してください。\n例: ABC123 営業部 新しい表示名")
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=prompt_text))
        return

    state = conversation_states.get(line_user_id, {})
    if state.get("expected") == "change_request":
        tokens = text.split()
        if len(tokens) < 3:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text="入力が不十分です。例: ABC123 営業部 新しい表示名"))
            return
        company_code = tokens[0]
        department = tokens[1]
        new_display_name = " ".join(tokens[2:])
        company = Company.query.filter_by(login_code=company_code).first()
        if company:
            user.company_id = company.id
            user.department = department
            user.line_display_name = new_display_name
            db.session.commit()
            reply = (f"所属企業が変更されました。\n新しい企業: {company.name}（企業コード: {company.login_code}）\n部署: {department}\n表示名: {new_display_name}")
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
        else:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=f"入力された企業コード '{company_code}' は存在しません。"))
        conversation_states.pop(line_user_id, None)
        return

    # PDF要求
    if text.lower() == "pdf" and not state:
        conversation_states[line_user_id] = {"expected": "pdf_option"}
        options_text = "PDFを選択してください:\n1. マニュアル\n2. 議事録\n3. 社内規定"
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=options_text))
        return
    elif state.get("expected") == "pdf_option":
        if text in ["1", "2", "3"]:
            conversation_states[line_user_id]["option"] = text
            conversation_states[line_user_id]["expected"] = "pdf_keyword"
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text="キーワードを入力してください。"))
            return
        else:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text="1, 2, 3 のいずれかを入力してください。"))
            return
    elif state.get("expected") == "pdf_keyword":
        chosen_option = state.get("option")
        if chosen_option == "1":
            category = "マニュアル"
        elif chosen_option == "2":
            category = "議事録"
        elif chosen_option == "3":
            category = "社内規定"
        else:
            category = None

        keyword = text
        docs = Document.query.filter(
            Document.company_id == user.company_id,
            Document.category == category,
            Document.title.ilike(f"%{keyword}%")
        ).all()
        if docs:
            domain = os.getenv("APP_DOMAIN", "http://127.0.0.1:5000")
            for doc in docs:
                token = generate_temp_pdf_token(doc.id)
                link = f"{domain}/documents/{doc.id}/view_pdf?token={token}"
                try:
                    line_bot_api.push_message(
                        user.line_id,
                        TextSendMessage(text=f"【PDF共有】該当PDF：{doc.title}\n{link}")
                    )
                except Exception as e:
                    print(f"LINE送信エラー: {e}")
        else:
            message = f"【検索通知】{user.line_display_name or user.username} さん、検索キーワード '{keyword}' の結果が見つかりませんでした。"
            notif = Notification(user_id=user.id, message=message)
            db.session.add(notif)
            db.session.commit()
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text="該当するPDFが見つかりませんでした。"))

        conversation_states.pop(line_user_id, None)
        return

    # 既定応答
    default_reply = (
        "PDF   登録されているPDFが共有されます\n"
        "ステータス   現在の登録内容が確認できます\n"
        "変更    現在の登録内容を変更できます"
    )
    line_bot_api.reply_message(event.reply_token, TextSendMessage(text=default_reply))

    ###############################################################################
    # LINE連携無効
    ###############################################################################
    @app.route("/line/login", methods=["GET"])
    def line_login():
    return jsonify({"error": "LINEログイン機能は無効です。"}), 403

    @app.route("/line/callback", methods=["GET", "POST"])
    def line_callback():
    return jsonify({"error": "LINEログイン機能は無効です. "}), 403

    @app.route("/line/register_info", methods=["POST"])
    @jwt_required
    def line_register_info():
    return jsonify({"error": "LINE連携機能（登録）は無効です."}), 403

    @app.route("/line/link", methods=["POST"])
    @jwt_required
    def line_link():
    return jsonify({"error": "LINE連携機能（リンク）は無効です."}), 403

    @app.route("/line/pending", methods=["GET"])
    @jwt_required
    def line_pending():
    return jsonify({"error": "LINE連携機能（申請一覧）は無効です."}), 403

    @app.route("/line/approve", methods=["POST"])
    @jwt_required
    def line_approve():
    return jsonify({"error": "LINE連携機能（承認）は無効です."}), 403

    @app.route("/line/reject", methods=["POST"])
    @jwt_required
    def line_reject():
    return jsonify({"error": "LINE連携機能（拒否）は無効です."}), 403

    ###############################################################################
    # ブロック、解除、承認
    ###############################################################################
    @app.route('/line/users/<int:user_id>/block', methods=['POST'])
    @jwt_required
    def block_line_user(user_id):
    if g.current_user.role not in ['env', 'admin']:
        return jsonify({"error": "Access denied"}), 403
    target = User.query.get_or_404(user_id)
    if g.current_user.role != 'env':
        if target.company_id != g.current_user.company_id:
            return jsonify({"error": "他社ユーザーへの操作はできません"}), 403
    target.is_blocked = True
    db.session.commit()
    return jsonify({"message": f"{target.line_display_name or target.username} をブロックしました"})

    @app.route('/line/users/<int:user_id>/unblock', methods=['POST'])
    @jwt_required
    def unblock_line_user(user_id):
    if g.current_user.role not in ['env', 'admin']:
        return jsonify({"error": "Access denied"}), 403
    target = User.query.get_or_404(user_id)
    if g.current_user.role != 'env':
        if target.company_id != g.current_user.company_id:
            return jsonify({"error": "他社ユーザーへの操作はできません"}), 403
    target.is_blocked = False
    db.session.commit()
    return jsonify({"message": f"{target.line_display_name or target.username} のブロックを解除しました"})

    @app.route('/line/users/<int:user_id>/approve', methods=['POST'])
    @jwt_required
    def approve_line_user(user_id):
    if g.current_user.role not in ['env', 'admin']:
        return jsonify({"error": "Access denied"}), 403
    target = User.query.get_or_404(user_id)
    if g.current_user.role != 'env':
        if target.company_id != g.current_user.company_id:
            return jsonify({"error": "他社ユーザーへの操作はできません"}), 403
    target.line_approved = True
    db.session.commit()
    return jsonify({"message": f"{target.line_display_name or target.username} を承認しました"})

    ###############################################################################
    # LINEユーザー一覧
    ###############################################################################
    @app.route('/line/users', methods=['GET'])
    @jwt_required
    def list_line_users():
    if g.current_user.role not in ['env', 'admin']:
        return jsonify({"error": "Access denied"}), 403
    if g.current_user.role == 'env':
        users = User.query.filter(User.line_id.isnot(None)).all()
    else:
        users = User.query.filter(
            User.line_id.isnot(None),
            User.company_id == g.current_user.company_id
        ).all()
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "line_display_name": u.line_display_name or u.username,
            "department": u.department or "",
            "is_blocked": u.is_blocked,
            "line_approved": u.line_approved,
            "created_at": to_jst(u.created_at)
        })
    return jsonify({"users": result})


    @app.route("/videos/<int:video_id>/update_transcription", methods=["POST"])
    def update_transcription(video_id):
    api_key = request.headers.get("Authorization", "").replace("Bearer ", "")
    if api_key != os.getenv("INTERNAL_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    whisper_text = data.get("whisper_text")
    if not whisper_text:
        return jsonify({"error": "No text provided"}), 400

    video = Video.query.get(video_id)
    if not video:
        return jsonify({"error": "Video not found"}), 404

    video.whisper_text = whisper_text
    db.session.commit()
    return jsonify({"message": "Transcription updated"})


    ###############################################################################
    # PDFリンク共有
    ###############################################################################
    @app.route('/line/share_pdf', methods=['POST'])
    @jwt_required
    def line_share_pdf():
    if g.current_user.role not in ['env', 'admin']:
        return jsonify({"error": "Access denied"}), 403
    data = get_request_data()
    doc_id = data.get("document_id")
    company_id = data.get("company_id")
    if not doc_id or not company_id:
        return jsonify({"error": "document_id and company_id are required"}), 400
    if g.current_user.role != 'env':
        if g.current_user.company_id != int(company_id):
            return jsonify({"error": "他社PDFの共有はできません"}), 403
    token = generate_temp_pdf_token(doc_id)
    domain = os.getenv("APP_DOMAIN", "http://127.0.0.1:5000")
    view_url = f"{domain}/documents/{doc_id}/view_pdf?token={token}"

    users = User.query.filter_by(company_id=company_id, line_approved=True).all()
    if not users:
        return jsonify({"error": "No linked LINE users found for this company"}), 404

    results = []
    for user in users:
        try:
            line_bot_api.push_message(
                user.line_id,
                TextSendMessage(text=f"【PDF共有】新しいPDFリンク: {view_url}")
            )
            results.append(f"Sent to {user.line_display_name or user.username}")
        except Exception as e:
            results.append(f"Failed to send to {user.line_display_name or user.username}: {str(e)}")
    return jsonify({"message": "PDF link share executed", "details": results})

    ###############################################################################
    # 動画アップロード（Cloudinary対応）
    ###############################################################################
    @app.route("/videos/upload", methods=["POST"])
    @jwt_required
    def upload_video():
    try:
        user_id = g.current_user.id
        title = request.form.get("title") or "Untitled Video"
        file = request.files.get("video_file")
        if not file:
            return jsonify({"error": "ファイルがアップロードされていません"}), 400

        generation_mode = request.form.get("generation_mode", "manual")

        # 1) Cloudinaryへアップロード（try内に入れる）
        try:
            video_url = upload_to_cloudinary(
                file,
                resource_type="video",
                folder="documentor/videos"
            )
            print(f"[DEBUG] Cloudinaryアップロード結果: {video_url}")
        except Exception as e:
            print(f"[ERROR] Cloudinaryアップロード失敗: {str(e)}")
            return jsonify({"error": "Cloudinaryへの動画アップロード中に例外が発生しました"}), 500

        # 2) Videoレコード登録
        video = Video(
            title=title,
            cloudinary_url=video_url,
            user_id=user_id,
            company_id=g.current_user.company_id
        )
        db.session.add(video)
        db.session.commit()

        # 3) 画像ファイルがあればOCR
        image_files = request.files.getlist("image_files")
        ocr_results = []
        if image_files:
            for image in image_files:
                # OCR用に一時保存
                img_filename = secure_filename(image.filename)
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ocr_{img_filename}")
                image.save(temp_path)
                try:
                    img_obj = Image.open(temp_path)
                    ocr_text = pytesseract.image_to_string(img_obj, lang='jpn')
                    ocr_results.append(f"画像 {img_filename} のOCR結果:\n{ocr_text.strip()}")
                except Exception as e:
                    ocr_results.append(f"画像 {img_filename} のOCR失敗: {str(e)}")
                finally:
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass

        if ocr_results:
            video.ocr_text = "\n".join(ocr_results)
            db.session.commit()

        # 4) Whisper解析＋クイズ生成
        try:
            print("[DEBUG] タスク送信前: video_id =", video.id)
            result = transcribe_video_task.delay(video.cloudinary_url, video.id)
            print("[DEBUG] タスク送信後, タスクID:", result.id)
        except Exception as e:
            print(f"[ERROR] 非同期タスク送信失敗: {str(e)}")

        return jsonify({"message": "アップロード成功", "video_id": video.id})


    @app.route('/videos/my', methods=['GET'])
    @login_required
    def get_my_videos():
    user_id = current_user.id
    videos = Video.query.filter_by(user_id=user_id).order_by(Video.created_at.desc()).all()
    return jsonify({
        "videos": [
            {
                "id": v.id,
                "title": v.title,
                "created_at": to_jst(v.created_at)
            }
            for v in videos
        ]
    })




    @app.route('/videos/<int:video_id>/view', methods=['GET'])
    @jwt_required
    def view_video(video_id):
    video = Video.query.get_or_404(video_id)
    if g.current_user.role != 'env':
        if video.company_id != g.current_user.company_id:
            return jsonify({"error": "他社の動画は閲覧できません"}), 403
    quiz = Quiz.query.filter_by(video_id=video.id).first()
    return jsonify({
        "id": video.id,
        "title": video.title,
        "created_at": to_jst(video.created_at),
        "cloudinary_url": video.cloudinary_url,
        "summary_text": video.summary_text or "要約がありません",
        "quiz_text": quiz.auto_quiz_text if quiz and quiz.auto_quiz_text else "クイズがありません"
    })

    ###############################################################################
    # ステップ画像アップロード（まだクラウド対応したい場合は書き換え可）
    ###############################################################################
    @app.route('/videos/<int:video_id>/steps/<int:step_id>/upload_image', methods=['POST'])
    @login_required
    def upload_step_image(video_id, step_id):
    step = VideoStep.query.filter_by(id=step_id, video_id=video_id).first()
    if not step:
        return jsonify({"error": "ステップが見つかりません"}), 404
    if current_user.role != 'env' and step.video.company_id != current_user.company_id:
        return jsonify({"error": "他社のステップは操作できません"}), 403

    file = request.files.get('image')
    if not file:
        return jsonify({"error": "画像ファイルがありません"}), 400

    # Cloudinaryにアップする
    image_url = upload_to_cloudinary(
        file,
        resource_type="image",
        folder="documentor/step_images"
    )
    if not image_url:
        return jsonify({"error": "Cloudinary画像アップロード失敗"}), 500

    attachment = StepAttachment(step_id=step.id, cloudinary_url=image_url, filetype='image')
    db.session.add(attachment)
    db.session.commit()

    return jsonify({"message": "画像をアップロードしました", "cloudinary_url": image_url})

    @app.route('/videos/<int:video_id>/steps_with_images', methods=['GET'])
    @login_required
    def get_steps_with_images(video_id):
    video = Video.query.get_or_404(video_id)
    if current_user.role != 'env' and video.company_id != current_user.company_id:
        return jsonify({"error": "他社の動画は閲覧できません"}), 403

    steps = VideoStep.query.filter_by(video_id=video_id).order_by(VideoStep.order).all()
    result = []
    for step in steps:
        attachments = [{
            "id": att.id,
            "cloudinary_url": att.cloudinary_url
        } for att in step.attachments if att.filetype == 'image']
        result.append({
            "id": step.id,
            "title": step.title,
            "description": step.description,
            "time_start": step.time_start,
            "time_end": step.time_end,
            "order": step.order,
            "attachments": attachments
        })
    return jsonify({"steps": result})

    ###############################################################################
    # 動画解析
    ###############################################################################
    @app.route('/videos/<int:video_id>/analyze', methods=['GET'])
    @jwt_required
    def analyze_video(video_id):
    try:
        video = Video.query.get_or_404(video_id)
        if g.current_user.role != 'env' and video.company_id != g.current_user.company_id:
            return jsonify({"error": "他社の動画は解析できません"}), 403

        images_info = ""
        steps = VideoStep.query.filter_by(video_id=video_id).order_by(VideoStep.order).all()
        for step in steps:
            image_texts = []
            for att in step.attachments:
                if att.filetype == 'image':
                    # CloudinaryURLからDLしてOCR
                    try:
                        resp = requests.get(att.cloudinary_url)
                        if resp.status_code == 200:
                            temp_img_path = os.path.join(app.config['UPLOAD_FOLDER'], "temp_step_img.png")
                            with open(temp_img_path, "wb") as f:
                                f.write(resp.content)
                            img = Image.open(temp_img_path)
                            ocr_result = pytesseract.image_to_string(img, lang='jpn')
                            image_texts.append(f"画像のOCR結果:\n{ocr_result.strip()}")
                            os.remove(temp_img_path)
                        else:
                            image_texts.append(f"画像ダウンロード失敗: {att.cloudinary_url}")
                    except Exception as e:
                        image_texts.append(f"画像OCR失敗: {str(e)}")
            if image_texts:
                images_info += f"【ステップ {step.order}】\n" + "\n".join(image_texts) + "\n\n"

        if video.ocr_text:
            images_info += f"【アップロード画像OCR結果】\n{video.ocr_text}\n\n"

        generation_mode = request.args.get("generation_mode", "manual")
        if generation_mode == "minutes":
            prompt_header = "以下の動画書き起こしと画像OCR結果から、会議の議事録として、主要議題、決定事項、アクションアイテムを生成してください。"
        else:
            prompt_header = "以下の動画書き起こしと画像OCR結果から、操作マニュアルとして、各ステップの手順と説明を生成してください。"

        prompt = (
            f"{prompt_header}\n\n"
            "【音声書き起こし】\n" + (video.whisper_text or "") + "\n\n" +
            "【画像OCR結果】\n" + images_info + "\n\n" +
            "上記の内容に基づいて、ステップごとの操作手順と説明を日本語で出力してください。"
        )

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "あなたはプロのマニュアル作成者です。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
            max_tokens=1000
        )
        analysis_text = response.choices[0].message.content.strip()
        return jsonify({"analysis": analysis_text})

    except Exception as e:
        print("動画解析エラー:", e)
        return jsonify({"error": str(e)}), 500

    ###############################################################################
    # ENV企業管理
    ###############################################################################
    @app.route('/companies/list', methods=['GET'])
    @jwt_required
    def list_companies():
    if g.current_user.role != "env":
        return jsonify({"error": "Access denied"}), 403
    companies = Company.query.all()
    result = []
    for c in companies:
        result.append({
            "id": c.id,
            "name": c.name,
            "login_code": c.login_code,
            "created_at": to_jst(c.created_at),
            "subscription_end": to_jst(c.updated_at + timedelta(days=30)) if c.updated_at else None
        })
    return jsonify({"companies": result})

    @app.route('/companies/add', methods=['POST'])
    @jwt_required
    def add_company():
    if g.current_user.role != "env":
        return jsonify({"error": "Access denied"}), 403
    data = get_request_data()
    name = data.get("name")
    if not name:
        return jsonify({"error": "企業名が必要です"}), 400
    login_code = generate_login_code()
    new_company = Company(name=name, login_code=login_code)
    db.session.add(new_company)
    db.session.commit()
    return jsonify({"message": "企業を追加しました", "login_code": login_code})

    @app.route('/companies/<int:company_id>/update', methods=['POST'])
    @jwt_required
    def update_company(company_id):
    if g.current_user.role != "env":
        return jsonify({"error": "Access denied"}), 403
    company = Company.query.get_or_404(company_id)
    data = get_request_data()
    company.name = data.get("name", company.name)
    company.login_code = data.get("login_code", company.login_code)
    if data.get("password"):
        user = User.query.filter_by(company_id=company.id).first()
        if user:
            user.set_password(data["password"])
    db.session.commit()
    return jsonify({"message": "企業情報を更新しました"})

    @app.route('/companies/<int:company_id>/update_subscription', methods=['POST'])
    @jwt_required
    def update_subscription(company_id):
    if g.current_user.role != "env":
        return jsonify({"error": "Access denied"}), 403
    company = Company.query.get_or_404(company_id)
    company.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({
        "message": "サブスクリプションを30日延長しました",
        "subscription_end": to_jst(company.updated_at + timedelta(days=30))
    })

    @app.route('/companies/<int:company_id>/delete', methods=['POST'])
    @jwt_required
    def delete_company(company_id):
    if g.current_user.role != "env":
        return jsonify({"error": "Access denied"}), 403
    company = Company.query.get_or_404(company_id)
    db.session.delete(company)
    db.session.commit()
    return jsonify({"message": "企業を削除しました"})

    ###############################################################################
    # PDF関連 (Cloudinary対応)
    ###############################################################################
    @app.route('/documents/upload', methods=['POST'])
    @jwt_required
    def upload_document():
    try:
        if g.current_user.role not in ['env', 'admin']:
            return jsonify({"error": "Access denied"}), 403
        data = request.form
        title = data.get("title")
        category = data.get("category")
        file = request.files.get("document_file")
        if not title or not category or not file:
            return jsonify({"error": "title, category and document_file are required"}), 400
        if category not in ["マニュアル", "社内規定", "議事録"]:
            return jsonify({"error": "カテゴリはマニュアル、社内規定、議事録のいずれかです"}), 400

        # Cloudinaryにアップロード（PDFは resource_type="raw" が無難）
        pdf_url = upload_to_cloudinary(
            file,
            resource_type="raw",
            folder="documentor/pdfs"
        )
        if not pdf_url:
            return jsonify({"error": "CloudinaryへのPDFアップロードに失敗しました"}), 500

        company_id = g.current_user.company_id if g.current_user.role != 'env' else None

        doc = Document(
            title=title,
            cloudinary_url=pdf_url,
            department="",
            category=category,
            company_id=company_id
        )
        db.session.add(doc)
        db.session.commit()
        return jsonify({"message": "Document uploaded", "document_id": doc.id})
    except Exception as ex:
        print("PDFアップロードエラー:", ex)
        return jsonify({"error": f"PDFアップロードに失敗しました: {str(ex)}"}), 500

    @app.route('/documents/<int:doc_id>/update', methods=['POST'])
    @jwt_required
    def update_document(doc_id):
    try:
        if g.current_user.role not in ['env', 'admin']:
            return jsonify({"error": "Access denied"}), 403
        doc = Document.query.get_or_404(doc_id)
        if g.current_user.role != 'env':
            if doc.company_id != g.current_user.company_id:
                return jsonify({"error": "他社のPDFは更新できません"}), 403

        data = request.form
        new_title = data.get("title")
        new_category = data.get("category")

        if new_title:
            doc.title = new_title
        if new_category:
            if new_category not in ["マニュアル", "社内規定", "議事録"]:
                return jsonify({"error": "カテゴリはマニュアル、社内規定、議事録のいずれかです"}), 400
            doc.category = new_category

        db.session.commit()
        return jsonify({"message": "Document updated"})
    except Exception as ex:
        print("PDF更新エラー:", ex)
        return jsonify({"error": f"PDF更新に失敗しました: {str(ex)}"}), 500

    @app.route('/documents/list', methods=['GET'])
    @jwt_required
    def list_documents():
    try:
        if g.current_user.role == 'env':
            query = Document.query
        else:
            query = Document.query.filter_by(company_id=g.current_user.company_id)

        category = request.args.get("category")
        if category:
            query = query.filter_by(category=category)

        docs = query.all()
        result = []
        for doc in docs:
            result.append({
                "id": doc.id,
                "title": doc.title,
                "department": doc.department,
                "category": doc.category,
                "created_at": to_jst(doc.created_at),
                # cloudinary_urlを返す
                "cloudinary_url": doc.cloudinary_url
            })
        return jsonify({"documents": result})
    except Exception as ex:
        print("PDF一覧取得エラー:", ex)
        return jsonify({"error": f"PDF一覧取得でエラー: {str(ex)}"}), 500

    @app.route('/documents/publish', methods=['POST'])
    @jwt_required
    def publish_document():
    """
    HTMLからPDFを生成し、一時的に保存した後にCloudinaryへアップロードする形にしてもよい。
    今回はローカル保存→DBにfilename保存しているが、Cloudinaryに乗せ換えるなら同様にupload_to_cloudinary()を利用。
    """
    try:
        data = get_request_data()
        title = data.get("title")
        content = data.get("content")
        generation_mode = data.get("generation_mode", "manual")

        if not title or not content:
            return jsonify({"error": "title and content are required"}), 400

        if generation_mode == "minutes":
            category = "議事録"
        else:
            category = "マニュアル"

        html = f"""
        <html>
            <head>
            <meta charset="utf-8">
            <style>
                body {{
                font-family: "Noto Sans JP", sans-serif;
                margin: 20px;
                line-height: 1.6;
                white-space: pre-wrap;
                }}
                h1 {{
                font-size: 1.5em;
                margin-bottom: 0.5em;
                }}
                .content {{
                white-space: pre-wrap;
                }}
            </style>
            <title>{title}</title>
            </head>
            <body>
            <h1>{title}</h1>
            <div class="content">{content}</div>
            </body>
        </html>
        """
        pdf_data = pdfkit.from_string(html, False, configuration=pdfkit_config)

        # 一時ファイルに保存
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        temp_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{timestamp}_{secure_filename(title)}.pdf")
        with open(temp_pdf_path, "wb") as f:
            f.write(pdf_data)

        # Cloudinaryへアップ
        pdf_url = None
        with open(temp_pdf_path, "rb") as f:
            pdf_url = upload_to_cloudinary(
                f,
                resource_type="raw",
                folder="documentor/pdfs"
            )

        if not pdf_url:
            return jsonify({"error": "CloudinaryへのPDFアップロードに失敗しました"}), 500

        company_id = g.current_user.company_id if g.current_user.role != 'env' else None
        doc = Document(
            title=title,
            cloudinary_url=pdf_url,
            department="",
            category=category,
            company_id=company_id
        )
        db.session.add(doc)
        db.session.commit()

        # 一時ファイル削除
        try:
            os.remove(temp_pdf_path)
        except:
            pass

        return jsonify({"message": "PDFが発行され、管理に追加されました", "document_id": doc.id})
    except Exception as ex:
        print("PDF発行エラー:", ex)
        return jsonify({"error": f"PDF生成に失敗しました: {str(ex)}"}), 500

    @app.route('/videos/<int:video_id>/summary_pdf', methods=['GET'])
    @login_required
    def summary_pdf_route(video_id):
    video = Video.query.get_or_404(video_id)
    if current_user.role != 'env' and video.company_id != current_user.company_id:
        return jsonify({"error": "他社の動画PDF生成はできません"}), 403
    if not video.summary_text:
        return jsonify({"error": "No summary available. Generate summary first."}), 400
    try:
        html = f"""
        <html>
            <head>
            <meta charset="utf-8">
            <style>
                body {{
                font-family: "Noto Sans JP", sans-serif;
                margin: 20px;
                line-height: 1.6;
                white-space: pre-wrap;
                }}
                p {{
                white-space: pre-wrap;
                }}
            </style>
            <title>Summary PDF</title>
            </head>
            <body>
            <h1>{video.title} 要約</h1>
            <p>{video.summary_text}</p>
            </body>
        </html>
        """
        pdf = pdfkit.from_string(html, False, configuration=pdfkit_config)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename=summary_{video.id}.pdf'
        return response
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

    @app.route('/videos/<int:video_id>/quiz_pdf', methods=['GET'])
    @login_required
    def quiz_pdf_route(video_id):
    quiz = Quiz.query.filter_by(video_id=video_id).first()
    if not quiz or not quiz.auto_quiz_text:
        return jsonify({"error": "No auto-generated quiz available."}), 400
    video = Video.query.get_or_404(video_id)
    if current_user.role != 'env' and video.company_id != current_user.company_id:
        return jsonify({"error": "他社のクイズPDF生成はできません"}), 403
    try:
        html = f"""
        <html>
            <head>
            <meta charset="utf-8">
            <style>
                body {{
                font-family: "Noto Sans JP", sans-serif;
                margin: 20px;
                line-height: 1.6;
                white-space: pre-wrap;
                }}
                p {{
                white-space: pre-wrap;
                }}
            </style>
            <title>Quiz PDF</title>
            </head>
            <body>
            <h1>Quiz for Video {video_id}</h1>
            <p>{quiz.auto_quiz_text}</p>
            </body>
        </html>
        """
        pdf = pdfkit.from_string(html, False, configuration=pdfkit_config)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename=quiz_{video_id}.pdf'
        return response
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

    ###############################################################################
    # PDF閲覧 (Cloudinary版の場合はURLを直接返す or ダウンロード)
    ###############################################################################
    @app.route('/documents/<int:doc_id>/view_pdf', methods=['GET'])
    def document_view_pdf(doc_id):
    """
    トークン検証後、Document.cloudinary_urlを直接返すか
    PDFバイナリをダウンロードして返すかのどちらか。
    ここでは例としてローカルファイルではなく、Cloudinaryから取得して返す方法にしてもよい。
    """
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "Token required"}), 401
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        if payload.get("doc_id") != doc_id:
            return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401

    doc = Document.query.get_or_404(doc_id)
    # ここではCloudinaryのURLを持っているので、直接リダイレクトでもよい
    # 例：redirect(doc.cloudinary_url)
    # あるいはダウンロード→返却も可
    # ここではサンプルとして元ローカルコードを残すが、Cloudinaryで一元管理するなら変更推奨

    # ローカルにファイルはもう無い想定なので「PDF file not found」になる可能性大
    # 必要に応じて doc.cloudinary_url を使ってダウンロード返却に書き換える
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.cloudinary_url)
    if not os.path.exists(pdf_path):
        return jsonify({"error": "PDF file not found"}), 404

    user_id = payload.get('user_id')
    log_entry = PDFViewLog(
        user_id=user_id,
        document_id=doc.id,
        timestamp=datetime.utcnow(),
        ip_address=request.remote_addr
    )
    db.session.add(log_entry)
    db.session.commit()

    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()
    response = make_response(pdf_data)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=document_{doc_id}.pdf'
    return response

    @app.route('/documents/<int:doc_id>/generate_view_link', methods=['POST'])
    @login_required
    def generate_view_link(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'env' and doc.company_id != current_user.company_id:
        return jsonify({"error": "他社のPDFはリンク生成できません"}), 403
    token = generate_temp_pdf_token(doc_id)
    domain = os.getenv("APP_DOMAIN", "http://127.0.0.1:5000")
    view_url = f"{domain}/documents/{doc_id}/view_pdf?token={token}"
    return jsonify({"view_url": view_url})

    ###############################################################################
    # 通知 + 検索ログ
    ###############################################################################
    @app.route('/notifications', methods=['GET'])
    @jwt_required
    def get_notifications():
    try:
        user_id = g.current_user.id
        notifs = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).all()
        notif_data = []
        for n in notifs:
            notif_data.append({
                "id": n.id,
                "message": n.message,
                "created_at": to_jst(n.created_at),
                "read_flag": n.read_flag
            })

        search_logs_data = []
        if g.current_user.role in ['admin', 'env']:
            if g.current_user.role == 'env':
                logs = SearchLog.query.order_by(SearchLog.created_at.desc()).all()
            else:
                logs = SearchLog.query.join(User, User.id == SearchLog.user_id)\
                    .filter(User.company_id == g.current_user.company_id)\
                    .order_by(SearchLog.created_at.desc()).all()
            for sl in logs:
                user_ = User.query.get(sl.user_id) if sl.user_id else None
                line_name = user_.line_display_name if (user_ and user_.line_display_name) else (user_.username if user_ else "不明ユーザー")
                search_logs_data.append({
                    "search_id": sl.id,
                    "line_display_name": line_name,
                    "keyword": sl.keyword,
                    "found_count": sl.found_count,
                    "searched_at": to_jst(sl.created_at)
                })

        return jsonify({
            "notifications": notif_data,
            "search_logs": search_logs_data
        })
    except Exception as ex:
        print("通知取得エラー:", ex)
        return jsonify({"error": f"通知取得でエラー: {str(ex)}"}), 500

    @app.route('/notifications/mark_read', methods=['POST'])
    @jwt_required
    def mark_notification_read():
    data = get_request_data()
    notif_id = data.get("notification_id")
    if not notif_id:
        return jsonify({"error": "notification_id is required"}), 400
    notif = Notification.query.get(notif_id)
    if not notif or notif.user_id != g.current_user.id:
        return jsonify({"error": "Notification not found or access denied"}), 404
    notif.read_flag = True
    db.session.commit()
    return jsonify({"message": "Notification marked as read"})

    @app.route('/search', methods=['GET'])
    @jwt_required
    def search_documents():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return jsonify({"error": "keyword is required"}), 400
    search_log = SearchLog(
        user_id=g.current_user.id,
        keyword=keyword,
        created_at=datetime.utcnow()
    )
    db.session.add(search_log)
    db.session.commit()

    if g.current_user.role == 'env':
        docs = Document.query.filter(
            (Document.title.like(f"%{keyword}%")) |
            (Document.department.like(f"%{keyword}%")) |
            (Document.category.like(f"%{keyword}%"))
        ).all()
    else:
        docs = Document.query.filter(
            Document.company_id == g.current_user.company_id
        ).filter(
            (Document.title.like(f"%{keyword}%")) |
            (Document.department.like(f"%{keyword}%")) |
            (Document.category.like(f"%{keyword}%"))
        ).all()

    search_log.found_count = len(docs)
    db.session.commit()

    results = []
    for doc in docs:
        results.append({
            "id": doc.id,
            "title": doc.title,
            "department": doc.department,
            "category": doc.category,
            "created_at": to_jst(doc.created_at)
        })

    if not docs:
        message = f"【検索通知】{g.current_user.line_display_name or g.current_user.username} さん、検索キーワード '{keyword}' の結果が見つかりませんでした。"
        notif = Notification(user_id=g.current_user.id, message=message)
        db.session.add(notif)
        db.session.commit()

    return jsonify({"results": results})

    ###############################################################################
    # JWT保護テスト
    ###############################################################################
    @app.route('/jwt/protected', methods=['GET'])
    @jwt_required
    def jwt_protected_route():
    return jsonify({"message": "JWT is valid. Protected content accessible."})

    ###############################################################################
    # アカウント更新
    ###############################################################################
    @app.route('/account/update', methods=['POST'])
    @login_required
    def account_update():
    try:
        data = get_request_data()
        current_password = data.get("current_password")
        new_username = data.get("new_username")
        new_password = data.get("new_password")

        if not current_password:
            return jsonify({"error": "現在のパスワードが必要です"}), 400
        if not current_user.check_password(current_password):
            return jsonify({"error": "現在のパスワードが正しくありません"}), 400

        if new_username:
            current_user.username = new_username
        if new_password:
            current_user.set_password(new_password)
        db.session.commit()
        return jsonify({"message": "アカウント情報を更新しました"})
    except Exception as ex:
        print("アカウント更新エラー:", ex)
        return jsonify({"error": f"アカウント更新に失敗しました: {str(ex)}"}), 500

    ###############################################################################
    # 基本ルート
    ###############################################################################
    @app.route('/')
    def index():
    return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_route():
    if request.method == 'GET':
        return jsonify({"message": "Please POST username and password to login."})
    data = get_request_data()
    username_or_code = data.get('username')
    password = data.get('password')
    if not username_or_code or not password:
        return jsonify({"error": "Username and password required"}), 400

    # -- ENVユーザーのチェック (既存処理)
    if username_or_code in ENV_USERS and ENV_USERS[username_or_code]["password"] == password:
        user = User.query.filter_by(username=username_or_code).first()
        if not user:
            user = User(username=username_or_code, email=f"{username_or_code}@example.com", role="env")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        login_user(user)
        token = generate_jwt(user)
        return jsonify({"message": "Login successful", "role": user.role, "user_id": user.id, "token": token})

    # -- ユーザー名でログインする場合 (既存処理)
    user = User.query.filter_by(username=username_or_code).first()
    if user and user.check_password(password):
        if user.company_id:
            company = Company.query.get(user.company_id)
            if company:
                if is_subscription_expired(company):
                    return jsonify({"error": "This company's subscription has expired."}), 403

        login_user(user)
        token = generate_jwt(user)
        return jsonify({"message": "Login successful", "role": user.role, "user_id": user.id, "token": token})

    # -- 企業コードログイン
    company = Company.query.filter_by(login_code=username_or_code).first()
    if company:
        if is_subscription_expired(company):
            return jsonify({"error": "This company's subscription has expired."}), 403

        admin_user = User.query.filter_by(username=f"company_{company.id}").first()
        if not admin_user:
            suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            unique_email = f"company_{company.id}_{suffix}@example.com"
            admin_user = User(
                username=f"company_{company.id}",
                email=unique_email,
                role="admin",
                company_id=company.id
            )
            admin_user.set_password("default123")
            db.session.add(admin_user)
            db.session.commit()

        if admin_user.check_password(password):
            login_user(admin_user)
            token = generate_jwt(admin_user)
            return jsonify({"message": "Login successful", "role": admin_user.role, 
                            "user_id": admin_user.id, "token": token})
        else:
            return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"error": "Invalid credentials"}), 401

    def is_subscription_expired(company):
    if not company.updated_at:
        return True
    subscription_end = company.updated_at + timedelta(days=30)
    return datetime.utcnow() > subscription_end

    @app.route('/logout', methods=['POST'])
    @login_required
    def logout_route():
    try:
        log_entry = LogEntry(user_id=current_user.id, action="logout", ip_address=request.remote_addr)
        db.session.add(log_entry)
        db.session.commit()
        logout_user()
        return jsonify({"message": "Logged out"})
    except Exception as ex:
        print("ログアウトエラー:", ex)
        return jsonify({"error": "ログアウト中にエラーが発生しました"}), 500

    @app.route('/dashboard')
    @login_required
    def dashboard_route():
    if current_user.role == 'env':
        company_count = Company.query.count()
        recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10).all()
        logs_data = [{
            "id": log.id,
            "action": log.action,
            "timestamp": to_jst(log.timestamp),
            "ip_address": log.ip_address,
            "details": log.details
        } for log in recent_logs]
        return jsonify({
            "role": "env",
            "company_count": company_count,
            "recent_logs": logs_data
        })
    else:
        user_videos = Video.query.filter_by(user_id=current_user.id).order_by(Video.created_at.desc()).all()
        public_videos = Video.query.filter_by(is_public=True).order_by(Video.created_at.desc()).all()
        progress_records = Progress.query.filter_by(user_id=current_user.id).all()
        completion_percentage = (
            sum(p.completion_percentage for p in progress_records) / len(progress_records)
            if progress_records else 0
        )
        return render_template("user_dashboard.html",
                                user_videos=user_videos,
                                public_videos=public_videos,
                                completion_percentage=completion_percentage)
    from flask_migrate import Migrate
    migrate = Migrate(app, db)

    # === Renderなどでgunicornを使う想定だが、ローカルテストならこのままOK
    if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role='env').first():
            admin_username = os.getenv('ADMIN_USERNAME', 'admin')
            admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
            admin = User(username=admin_username, email='admin@example.com', role='env')
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()	

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)


