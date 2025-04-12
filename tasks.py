from celery import Celery
import os
from dotenv import load_dotenv
load_dotenv()

celery = Celery(
    'tasks',
    broker=os.getenv('REDIS_URL', 'redis://localhost:6380/0'),
    backend=os.getenv('REDIS_URL', 'redis://localhost:6380/0')
)

@celery.task
def transcribe_video_task(video_url, video_id):
    print(f"[DEBUG] Dummy transcribe task: {video_url}, {video_id}")
    return "dummy transcribe executed"

@celery.task(bind=True)
def generate_summary_and_quiz_task(self, video_id, transcript):
    print("[WARNING] Render上でgenerate_summary_and_quiz_taskは呼ばれるべきではありません")
    return "dummy"
