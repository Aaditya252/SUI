import numpy as np
from sklearn.ensemble import IsolationForest
import time
import json
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_data.json")


class ThreatDetector:
    def __init__(self):
        self.model = None
        self.contamination = 0.05
        self.n_estimators = 100
        self.trained = False
        self.training_data = []
        self._init_model()

    def _init_model(self):
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            warm_start=True
        )
        self._load_training_data()

    def _load_training_data(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "r") as f:
                    data = json.load(f)
                self.training_data = data.get("samples", [])
                if len(self.training_data) >= 10:
                    self._train()
            except Exception:
                self.training_data = []

    def _save_training_data(self):
        try:
            data = {"samples": self.training_data[-1000:], "updated": time.time()}
            with open(MODEL_PATH, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    def _train(self):
        if len(self.training_data) < 10:
            return
        X = np.array(self.training_data[-500:])
        self.model.fit(X)
        self.trained = True

    def extract_features(self, request_data):
        features = []
        features.append(len(request_data.get("path", "")))
        features.append(len(request_data.get("body", "")))
        features.append(len(request_data.get("query", "")))
        features.append(len(request_data.get("headers", {})))
        features.append(request_data.get("num_params", 0))
        features.append(self._compute_entropy(request_data.get("body", "")))
        features.append(request_data.get("request_rate", 0))
        return np.array(features).reshape(1, -1)

    def _compute_entropy(self, data):
        if not data:
            return 0
        prob = [float(data.count(c)) / len(data) for c in set(data)]
        return -sum(p * np.log2(p) for p in prob if p > 0)

    def analyze(self, request_data):
        features = self.extract_features(request_data)
        features_list = features.flatten().tolist()

        if not self.trained:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "confidence": "LOW",
                "features": features_list,
                "message": "Model not yet trained (need 10+ samples)"
            }

        score = self.model.decision_function(features)[0]
        prediction = self.model.predict(features)[0]
        is_anomaly = bool(prediction == -1)
        anomaly_score = float(min(max(-score / 10 + 0.5, 0), 1))

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "raw_score": round(float(score), 4),
            "confidence": "HIGH" if abs(anomaly_score - 0.5) > 0.3 else "MEDIUM",
            "features": features_list,
            "message": "Anomalous request pattern detected" if is_anomaly else "Request appears normal"
        }

    def learn(self, request_data, was_malicious=False):
        features = self.extract_features(request_data)
        self.training_data.append(features.flatten().tolist())
        if was_malicious:
            for _ in range(3):
                noisy = features.flatten() + np.random.normal(0, 0.1, features.shape[1])
                self.training_data.append(noisy.tolist())
        self._train()
        self._save_training_data()

    def get_model_stats(self):
        return {
            "trained": self.trained,
            "samples_collected": len(self.training_data),
            "contamination": self.contamination,
            "estimators": self.n_estimators
        }


threat_detector = ThreatDetector()
