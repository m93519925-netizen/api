FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc g++ curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=180s --retries=5 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["sh", "-c", "PYTHONMALLOC=malloc OMP_NUM_THREADS=1 TOKENIZERS_PARALLELISM=false uvicorn main:app --host 0.0.0.0 --port 7860 --workers 1 --timeout-keep-alive 30"]
