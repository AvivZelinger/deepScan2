#!/usr/bin/env python
import os
import sys
import struct
import numpy as np
import pandas as pd
import json
import warnings
from collections import defaultdict
from scapy.all import rdpcap, UDP, IP
from tensorflow.keras import models
import tensorflow as tf
import joblib
from pymongo import MongoClient
class BaseDPIModel:
    """בסיס למעטפת מודלים המטפלת בטעינה ופונקציונליות משותפת"""
    def __init__(self, model_path, custom_objects=None):
        self.model = models.load_model(model_path, custom_objects=custom_objects)
        
    def _predict_raw(self, X_features):
        """קבלת תחזית גולמית מהמודל הבסיסי"""
        return self.model.predict(X_features)


class ClassificationDPIModel(BaseDPIModel):
    """מעטפת למודלים של סיווג (is_dynamic, field_type)"""
    def __init__(self, model_path, custom_objects=None, label_encoder=None):
        super().__init__(model_path, custom_objects)
        self.label_encoder = label_encoder
        
    # def predict(self, X_features):
    #     """החזרת תחזית המחלקה"""
    #     raw_prediction = self._predict_raw(X_features)
    #     return np.argmax(raw_prediction, axis=1)[0]
        
    def predict(self, X_features):
        """החזרת תווית המחלקה באמצעות מקודד התוויות"""
        class_idx = np.argmax(self._predict_raw(X_features), axis=1)[0]
        if self.label_encoder:
            return self.label_encoder.inverse_transform([class_idx])[0]
        return class_idx


class RegressionDPIModel(BaseDPIModel):
    def __init__(self, model_path, custom_objects=None):
        super().__init__(model_path, custom_objects)
        self.fallback = None
    
    def set_fallback(self, fallback):
        self.fallback = fallback
        
    """מעטפת למודלים של רגרסיה (min/max size, min/max value)"""
    def predict(self, X_features):
        """החזרת תחזית רגרסיה מעובדת עם גיבוי לערכי NaN"""
        raw_prediction = self._predict_raw(X_features)
        value = float(raw_prediction[0][0])
        if np.isnan(value) and self.fallback is not None:
            return self.fallback
        return value

##########################################
# Encoder מותאם לסוגי NumPy לייצוא JSON
##########################################
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)