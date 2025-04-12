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

@celery.task(bind=True)
def generate_summary_and_quiz_task(self, video_id, transcript):
    print(f"[DEBUG] Dummy task: {video_id}, length={len(transcript)}")
    return "dummy task executed"
