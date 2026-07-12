FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc g++ curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download model từ HuggingFace khi build
RUN python -c "
from transformers import AutoTokenizer, AutoModelForSequenceClassification
model_id = 'dsdsdewe/hoibai-moderation-phobert'
print('Downloading tokenizer...')
AutoTokenizer.from_pretrained(model_id, cache_dir='./model')
print('Downloading model...')
AutoModelForSequenceClassification.from_pretrained(model_id, cache_dir='./model')
print('Done!')
"

COPY main.py .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=120s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1"]
