"""
HoiBai Content Moderation API
FastAPI server để chạy inference model phoBERT trên CPU
- Railway/Render compatible
- Health check endpoint
- Batch prediction support (real batch, không loop)
- Tối ưu CPU: dynamic quantization, thread control, inference_mode
"""

import os
import json
import re
import unicodedata
import time
from contextlib import asynccontextmanager
from typing import List, Optional

# Tối ưu CPU - set trước khi import torch
# Phải set trước import torch để có hiệu lực
os.environ.setdefault("OMP_NUM_THREADS", "4")
os.environ.setdefault("MKL_NUM_THREADS", "4")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Cho phép CPU dùng TF32 (nếu hỗ trợ) - tăng tốc độ matmul
torch.set_float32_matmul_precision('high')

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "./hoibai_moderation_model")
MAX_LENGTH = 128
THRESHOLD_SAFE = 0.75
BATCH_SIZE = 16

# Bật/tắt quantization INT8 (giảm 2-4x tốc độ inference + RAM)
# Set USE_QUANTIZATION=true để bật
USE_QUANTIZATION = os.environ.get("USE_QUANTIZATION", "true").lower() == "true"

LABEL_MAP = {0: "CLEAN", 1: "SPAM", 2: "TOXIC", 3: "MEANINGLESS"}
ACTION_MAP = {
    "CLEAN": "allow",
    "SPAM": "flag",
    "TOXIC": "block",
    "MEANINGLESS": "flag",
}

# ---------------------------------------------------------------------------
# Text cleaning (match training preprocessing)
# ---------------------------------------------------------------------------

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFC", text)
    text = re.sub(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        "[URL]",
        text,
    )
    text = re.sub(r"\b0\d{9,10}\b", "[PHONE]", text)
    text = re.sub(r"\S+@\S+\.\S+", "[EMAIL]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.lower()


# ---------------------------------------------------------------------------
# Model holder
# ---------------------------------------------------------------------------

class ModelHolder:
    def __init__(self):
        self.tokenizer: Optional[AutoTokenizer] = None
        self.model: Optional[AutoModelForSequenceClassification] = None
        self.device: Optional[torch.device] = None
        self.ready: bool = False

    def load(self):
        print(f"[INFO] Loading model from: {MODEL_DIR}")
        start = time.time()

        if not os.path.exists(MODEL_DIR):
            raise FileNotFoundError(f"Model directory not found: {MODEL_DIR}")

        self.device = torch.device("cpu")

        # Set số thread cho PyTorch (mặc định 4, override qua env)
        num_threads = int(os.environ.get("TORCH_NUM_THREADS", "4"))
        torch.set_num_threads(num_threads)
        torch.set_num_interop_threads(2)
        print(f"[INFO] PyTorch threads: {num_threads}")

        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)

        # Quantization INT8 cho các lớp Linear - giảm 2-4x inference time
        if USE_QUANTIZATION:
            print("[INFO] Applying dynamic quantization (INT8)...")
            self.model = torch.quantization.quantize_dynamic(
                self.model,
                {torch.nn.Linear},
                dtype=torch.qint8,
            )
            print("[INFO] Quantization done")

        self.model = self.model.to(self.device)
        self.model.eval()
        self.ready = True

        elapsed = time.time() - start
        print(f"[INFO] Model loaded in {elapsed:.2f}s")
        print(f"[INFO] Device: {self.device}")
        param_count = sum(p.numel() for p in self.model.parameters())
        print(f"[INFO] Parameters: {param_count:,}")

        # Warmup - chạy 1 request giả để JIT compile, cache warm
        self._warmup()

    def _warmup(self):
        """Chạy 1 inference warmup để JIT compile, tránh cold start lag."""
        print("[INFO] Warming up model...")
        start = time.time()
        dummy = "warmup test content"
        inputs = self.tokenizer(
            dummy,
            return_tensors="pt",
            padding="max_length",
            truncation=True,
            max_length=MAX_LENGTH,
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.inference_mode():
            _ = self.model(**inputs)
        print(f"[INFO] Warmup done in {time.time() - start:.2f}s")

    def predict(self, text: str, content_type: str = "question") -> dict:
        if not self.ready:
            raise RuntimeError("Model not loaded")

        cleaned = clean_text(text)
        combined = f"[{content_type.upper()}] {cleaned}"

        inputs = self.tokenizer(
            combined,
            return_tensors="pt",
            padding="max_length",
            truncation=True,
            max_length=MAX_LENGTH,
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        # inference_mode nhanh hơn no_grad ~10-20%
        with torch.inference_mode():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)
            pred = torch.argmax(probs, dim=-1).item()
            confidence = probs[0][pred].item()
            all_probs = probs[0].cpu().numpy()

        label = LABEL_MAP[pred]
        return {
            "text_preview": text[:100] + "..." if len(text) > 100 else text,
            "predicted_label": label,
            "label_id": pred,
            "confidence": round(confidence, 4),
            "action": ACTION_MAP[label],
            "all_scores": {
                LABEL_MAP[i]: round(float(p), 4) for i, p in enumerate(all_probs)
            },
            "should_block": label in ("SPAM", "TOXIC", "MEANINGLESS"),
        }

    def predict_batch(self, items: List[dict]) -> List[dict]:
        """Real batch prediction - tokenize & infer nhiều item cùng lúc."""
        if not self.ready:
            raise RuntimeError("Model not loaded")
        if not items:
            return []

        results = []
        # Chia thành các batch nhỏ để tránh OOM
        for i in range(0, len(items), BATCH_SIZE):
            batch = items[i:i + BATCH_SIZE]
            texts = []
            for it in batch:
                t = it.get("text", "")
                ct = it.get("type", "question")
                cleaned = clean_text(t)
                texts.append(f"[{ct.upper()}] {cleaned}")

            # Tokenize batch
            inputs = self.tokenizer(
                texts,
                return_tensors="pt",
                padding="max_length",
                truncation=True,
                max_length=MAX_LENGTH,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.inference_mode():
                outputs = self.model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                preds = torch.argmax(probs, dim=-1).cpu().numpy()
                confs = probs.max(dim=-1).values.cpu().numpy()

            for j, it in enumerate(batch):
                pred = int(preds[j])
                label = LABEL_MAP[pred]
                results.append({
                    "id": it.get("id"),
                    "text_preview": it.get("text", "")[:100],
                    "predicted_label": label,
                    "label_id": pred,
                    "confidence": round(float(confs[j]), 4),
                    "action": ACTION_MAP[label],
                    "should_block": label in ("SPAM", "TOXIC", "MEANINGLESS"),
                })

        return results


model_holder = ModelHolder()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    model_holder.load()
    yield
    print("[INFO] Shutting down...")


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="HoiBai Content Moderation API",
    description="API phân loại nội dung CLEAN/SPAM/TOXIC/MEANINGLESS cho nền tảng hỏi đáp bài tập",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class PredictRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000, description="Nội dung cần kiểm tra")
    type: str = Field(default="question", pattern="^(question|answer)$")


class BatchPredictRequest(BaseModel):
    items: List[dict] = Field(..., description="List các items, mỗi item có 'text', 'type', 'id' (optional)")


class PredictResponse(BaseModel):
    text_preview: str
    predicted_label: str
    label_id: int
    confidence: float
    action: str
    all_scores: dict
    should_block: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "service": "HoiBai Content Moderation API",
        "version": "1.1.0",
        "status": "ready" if model_holder.ready else "loading",
        "model": "vinai/phobert-base (fine-tuned, INT8 quantized)",
        "labels": LABEL_MAP,
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy" if model_holder.ready else "loading",
        "model_loaded": model_holder.ready,
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(req: PredictRequest):
    if not model_holder.ready:
        raise HTTPException(status_code=503, detail="Model chưa load xong")
    try:
        return model_holder.predict(req.text, req.type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
async def predict_batch(req: BatchPredictRequest):
    if not model_holder.ready:
        raise HTTPException(status_code=503, detail="Model chưa load xong")
    try:
        results = model_holder.predict_batch(req.items)
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check")
async def check_content(req: PredictRequest):
    """Endpoint đơn giản để tích hợp với PHP backend."""
    if not model_holder.ready:
        raise HTTPException(status_code=503, detail="Model chưa load xong")
    try:
        result = model_holder.predict(req.text, req.type)
        return {
            "is_clean": result["predicted_label"] == "CLEAN",
            "label": result["predicted_label"],
            "confidence": result["confidence"],
            "action": result["action"],
            "should_block": result["should_block"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Run local
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
