FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Train the optional ML model inside the image so it matches the installed
# scikit-learn version. Remove these two lines to run with rules only.
RUN python ml/build_dataset.py && python ml/train_model.py && rm -rf instance

RUN useradd --create-home phishguard && mkdir -p instance && chown -R phishguard /app
USER phishguard

EXPOSE 8000

# Apply database migrations, then start the production server.
CMD ["sh", "-c", "flask --app run db upgrade && gunicorn --workers 3 --bind 0.0.0.0:8000 --access-logfile - wsgi:app"]
