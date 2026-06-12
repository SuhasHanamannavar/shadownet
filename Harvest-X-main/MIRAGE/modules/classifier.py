"""
classifier.py
=============
Primary attacker classifier using the local ML model (sklearn ensemble).
Falls back to OpenAI GPT-4o if model not found or confidence < threshold.
"""

import os
import json
import time

import config
from modules.feature_extractor import extract

# ── Constants ─────────────────────────────────────────────────────────────────
MODEL_PATH = "./data/mirage_model.pkl"
CLASSES    = ["Bot", "APT", "Script Kiddie"]
CONFIDENCE_THRESHOLD = 0.65   # below this, defer to OpenAI fallback

# ── Lazy-load the ML pipeline ─────────────────────────────────────────────────
_pipeline = None

def _load_model():
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    if os.path.exists(MODEL_PATH):
        try:
            import joblib
            _pipeline = joblib.load(MODEL_PATH)
            print(f"[Classifier] ✓ Local ML model loaded from {MODEL_PATH}")
        except Exception as e:
            print(f"[Classifier] ✗ Failed to load ML model: {e}")
    else:
        print(f"[Classifier] ✗ No trained model found at {MODEL_PATH}. "
              "Run: python modules/train_model.py")
    return _pipeline


def _ml_classify(session_data: dict) -> dict | None:
    """Run the sklearn pipeline and return result dict, or None on failure."""
    model = _load_model()
    if model is None:
        return None

    try:
        import numpy as np
        features = extract(session_data)
        features_arr = np.array(features).reshape(1, -1)

        pred_idx  = model.predict(features_arr)[0]
        proba     = model.predict_proba(features_arr)[0]
        confidence = float(proba[pred_idx])
        label      = CLASSES[pred_idx]

        # Build human-readable reasoning from top features
        cmds = session_data.get("commands", [])
        reason = _build_reasoning(label, session_data)

        return {
            "type":       label,
            "confidence": round(confidence, 3),
            "reasoning":  reason,
            "source":     "local_ml",
        }
    except Exception as e:
        print(f"[Classifier] ML inference error: {e}")
        return None


def _build_reasoning(label: str, session_data: dict) -> str:
    """Generate a human-readable reasoning string from session stats."""
    cmds = session_data.get("commands", [])
    timings = session_data.get("timings", [])
    n = len(cmds)
    unique = len(set(cmds))
    mean_t = (sum(timings) / len(timings)) if timings else 0

    if label == "Bot":
        return (f"Automated behavior detected: {n} commands in {mean_t:.1f}s avg intervals, "
                f"low variety ({unique} unique). Likely credential stuffing or scanner.")
    elif label == "APT":
        return (f"Advanced threat detected: methodical recon over {n} commands, "
                f"{mean_t:.1f}s avg delay indicates human operator.")
    else:
        return (f"Noisy attacker: {n} commands including destructive patterns, "
                f"fast-paced ({mean_t:.1f}s avg). Classic script kiddie behavior.")


def _openai_classify(session_data: dict) -> dict:
    """Fallback to OpenAI when ML confidence is low or model unavailable."""
    try:
        import openai
        client = openai.OpenAI(api_key=config.OPENAI_API_KEY)

        commands = session_data.get("commands", [])
        prompt = f"""
Analyze this honeypot session. Commands executed: {commands}
Classify as EXACTLY ONE: Bot | APT | Script Kiddie
Return JSON with: type, confidence (0.0-1.0), reasoning (1 sentence).
"""
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity threat analyst. Output only valid JSON."},
                {"role": "user",   "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        result["source"] = "openai"
        return result
    except Exception as e:
        print(f"[Classifier] OpenAI fallback failed: {e}")
        return _heuristic_classify(session_data)


def _heuristic_classify(session_data: dict) -> dict:
    """Last-resort rule-based classifier when both ML and OpenAI fail."""
    cmds_str = " ".join(session_data.get("commands", [])).lower()
    timings  = session_data.get("timings", [])
    mean_t   = (sum(timings) / len(timings)) if timings else 0

    if "rm -rf" in cmds_str or "dd if=" in cmds_str or "mkfs" in cmds_str:
        return {"type": "Script Kiddie", "confidence": 0.80,
                "reasoning": "Destructive commands detected.", "source": "heuristic"}
    if mean_t > 5.0 and ("whoami" in cmds_str or "netstat" in cmds_str):
        return {"type": "APT", "confidence": 0.72,
                "reasoning": "Slow, methodical recon pattern.", "source": "heuristic"}
    if mean_t < 1.0 and ("wget" in cmds_str or "curl" in cmds_str):
        return {"type": "Bot", "confidence": 0.75,
                "reasoning": "Fast automated downloader.", "source": "heuristic"}
    return {"type": "Bot", "confidence": 0.55,
            "reasoning": "Default heuristic classification.", "source": "heuristic"}


def classify(session_data: dict) -> dict:
    """
    Main entry point.
    1. Try local ML model
    2. If confidence < threshold → refine with OpenAI
    3. If both fail → heuristic rules
    """
    if not session_data.get("commands"):
        return {"type": "Unknown", "confidence": 0.0,
                "reasoning": "No commands", "source": "none"}

    result = _ml_classify(session_data)

    if result and result["confidence"] >= CONFIDENCE_THRESHOLD:
        print(f"[Classifier] ML → {result['type']} ({result['confidence']:.2%})")
        return result

    # Low confidence — ask OpenAI to refine
    print(f"[Classifier] ML confidence low ({result['confidence'] if result else 'N/A'}), "
          "consulting OpenAI...")
    if config.OPENAI_API_KEY and config.OPENAI_API_KEY != "your-key-here":
        ai_result = _openai_classify(session_data)
        # Blend: prefer AI type but keep ML confidence if AI confident
        if result:
            ai_result["ml_type"]       = result["type"]
            ai_result["ml_confidence"] = result["confidence"]
        return ai_result

    # No API key — use heuristic
    return result if result else _heuristic_classify(session_data)
