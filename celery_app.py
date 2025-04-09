import os
from celery import Celery
from app_factory import create_app

flask_app = create_app()

def make_celery(app):
    celery = Celery(
        app.import_name,
        broker=os.getenv("REDIS_URL", "redis://localhost:6380/0"),
        backend=os.getenv("REDIS_URL", "redis://localhost:6380/0"),
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

celery = make_celery(flask_app)
