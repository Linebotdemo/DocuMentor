from celery import Celery
import os
import requests
from dotenv import load_dotenv
load_dotenv()

celery = Celery(
    'tasks',
    broker=os.getenv('REDIS_URL', 'redis://localhost:6380/0'),
    backend=os.getenv('REDIS_URL', 'redis://localhost:6380/0')
)

@celery.task
def transcribe_video_task(video_url, video_id):
    print(f"[DEBUG] タスク実行開始: video_url={video_url}, video_id={video_id}")
    whisper_api_url = os.getenv("WHISPER_API_URL", "http://localhost:8001/transcribe")
    try:
        response = requests.post(whisper_api_url, json={"video_url": video_url}, timeout=600)
        text = response.json().get("text", "")
        print(f"[DEBUG] Whisper結果: {text}")
        # DB保存などはFlask側で処理
        return text
    except Exception as e:
        print(f"[ERROR] Whisperタスクエラー: {str(e)}")
        return None
