# Dockerfile cho Railway / Render
# Pull model từ HuggingFace Hub lúc build (không cần push model lên GitHub)
# Chạy model phoBERT trên CPU với tối ưu

FROM python:3.10-slim

WORKDIR /app

# Cài system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements trước để cache layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY main.py .

# Pull model từ HuggingFace Hub lúc build
# Repo: dsdsdewe/hoibai-moderation-phobert
ARG HF_MODEL_REPO=dsdsdewe/hoibai-moderation-phobert
ENV HF_MODEL_REPO=${HF_MODEL_REPO}
ENV MODEL_DIR=/app/hoibai_moderation_model

RUN python -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='${HF_MODEL_REPO}', local_dir='${MODEL_DIR}')"

# Verify model đã download đủ files
RUN python -c "import os; files = os.listdir('${MODEL_DIR}'); print('Model files:', files); assert 'config.json' in files, 'Missing config.json'; assert 'model.safetensors' in files or 'pytorch_model.bin' in files, 'Missing model weights'"

# Cấu hình cho CPU
ENV OMP_NUM_THREADS=4
ENV MKL_NUM_THREADS=4
ENV TOKENIZERS_PARALLELISM=false

# Port
ENV PORT=8000

EXPOSE 8000

# Chạy với 1 worker (CPU của Railway/Render thường yếu)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--loop", "asyncio"]
