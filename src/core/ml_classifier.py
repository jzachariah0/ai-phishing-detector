"""
Machine Learning Classifier for Phishing Detection
Trains on real email data and provides predictions
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
import joblib
from pathlib import Path
from typing import Dict, List, Tuple
import re

class PhishingMLClassifier:
    """Machine Learning classifier for phishing email detection"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.pipeline = None
        self.feature_names = []
        self.training_accuracy = 0.0
        self.test_accuracy = 0.0
        self.model_path = Path("data/models")
        self.model_path.mkdir(parents=True, exist_ok=True)
    
    def preprocess_email_text(self, sender: str, subject: str, body: str) -> str:
        """Combine and preprocess email components"""
        # Combine all text components
        full_text = f"{sender} {subject} {body}"
        
        # Clean the text
        full_text = re.sub(r'http[s]?://[^\s<>"]+', ' URL_TOKEN ', full_text)  # Replace URLs
        full_text = re.sub(r'\b\d+\b', ' NUMBER_TOKEN ', full_text)  # Replace numbers
        full_text = re.sub(r'[^\w\s]', ' ', full_text)  # Remove special characters
        full_text = re.sub(r'\s+', ' ', full_text)  # Remove extra whitespace
        
        return full_text.lower().strip()
    
    def extract_advanced_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract advanced features from email data"""
        features_df = df.copy()
        
        # Text-based features
        features_df['text_combined'] = df.apply(
            lambda row: self.preprocess_email_text(row['sender'], row['subject'], row['body']), 
            axis=1
        )
        
        # Length features
        features_df['subject_length'] = df['subject'].str.len()
        features_df['body_length'] = df['body'].str.len()
        features_df['sender_length'] = df['sender'].str.len()
        
        # URL features
        features_df['url_count'] = df['body'].str.count(r'http[s]?://')
        features_df['has_urls'] = (features_df['url_count'] > 0).astype(int)
        
        # Urgency features
        urgency_keywords = ['urgent', 'immediate', 'asap', 'now', 'today', 'expires', 'deadline']
        features_df['urgency_keywords'] = df['subject'].str.lower().str.contains('|'.join(urgency_keywords)).astype(int)
        
        # Suspicious domain features
        suspicious_domains = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']
        features_df['suspicious_domain'] = df['body'].str.lower().str.contains('|'.join(suspicious_domains)).astype(int)
        
        # Authority spoofing
        authority_terms = ['microsoft', 'apple', 'amazon', 'paypal', 'google', 'bank']
        features_df['authority_spoofing'] = df['sender'].str.lower().str.contains('|'.join(authority_terms)).astype(int)
        
        # Email pattern features
        features_df['sender_has_dash'] = df['sender'].str.contains('-').astype(int)
        features_df['sender_has_numbers'] = df['sender'].str.contains(r'\d').astype(int)
        
        # Caps features
        features_df['subject_caps_ratio'] = df['subject'].apply(
            lambda x: sum(1 for c in x if c.isupper()) / len(x) if len(x) > 0 else 0
        )
        
        return features_df
    
    def train_model(self, dataset_path: str = "data/processed/email_dataset.csv"):
        """Train the ML model on email dataset"""
        print("Loading dataset...")
        df = pd.read_csv(dataset_path)
        
        print("Extracting features...")
        features_df = self.extract_advanced_features(df)
        
        # Prepare text data for TF-IDF
        X_text = features_df['text_combined']
        
        # Prepare numerical features
        numerical_features = [
            'subject_length', 'body_length', 'sender_length', 'url_count', 
            'has_urls', 'urgency_keywords', 'suspicious_domain', 
            'authority_spoofing', 'sender_has_dash', 'sender_has_numbers', 
            'subject_caps_ratio'
        ]
        X_numerical = features_df[numerical_features]
        
        # Target variable
        y = features_df['label']
        
        print("Creating ML pipeline...")
        # Create TF-IDF vectorizer for text
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),  # Use both single words and pairs
            min_df=1,  # Minimum document frequency
            max_df=0.95  # Maximum document frequency
        )
        
        # Transform text to TF-IDF features
        X_text_tfidf = self.vectorizer.fit_transform(X_text).toarray()
        
        # Combine text and numerical features
        X_combined = np.hstack([X_text_tfidf, X_numerical.values])
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print("Training Random Forest classifier...")
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'  # Handle imbalanced data
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        train_predictions = self.model.predict(X_train)
        test_predictions = self.model.predict(X_test)
        
        self.training_accuracy = accuracy_score(y_train, train_predictions)
        self.test_accuracy = accuracy_score(y_test, test_predictions)
        
        print(f"\n=== MODEL TRAINING RESULTS ===")
        print(f"Training Accuracy: {self.training_accuracy:.3f}")
        print(f"Test Accuracy: {self.test_accuracy:.3f}")
        
        print(f"\n=== DETAILED TEST RESULTS ===")
        print("Classification Report:")
        print(classification_report(y_test, test_predictions, target_names=['Legitimate', 'Phishing']))
        
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, test_predictions))
        
        # Feature importance
        feature_importance = self.model.feature_importances_
        
        # Get top features (text + numerical)
        text_feature_names = self.vectorizer.get_feature_names_out()
        all_feature_names = list(text_feature_names) + numerical_features
        
        # Sort by importance
        feature_importance_pairs = list(zip(all_feature_names, feature_importance))
        feature_importance_pairs.sort(key=lambda x: x[1], reverse=True)
        
        print(f"\n=== TOP 10 MOST IMPORTANT FEATURES ===")
        for i, (feature, importance) in enumerate(feature_importance_pairs[:10]):
            print(f"{i+1:2d}. {feature:<20} {importance:.4f}")
        
        # Save the model and vectorizer
        self.save_model()
        
        return self.test_accuracy
    
    def predict_email(self, sender: str, subject: str, body: str) -> Dict:
        """Predict if an email is phishing"""
        if self.model is None or self.vectorizer is None:
            raise ValueError("Model not trained. Call train_model() first.")
        
        # Preprocess the email
        text_combined = self.preprocess_email_text(sender, subject, body)
        
        # Extract numerical features
        numerical_features = self._extract_single_email_features(sender, subject, body)
        
        # Transform text to TF-IDF
        X_text_tfidf = self.vectorizer.transform([text_combined]).toarray()
        
        # Combine features
        X_combined = np.hstack([X_text_tfidf, [numerical_features]])
        
        # Make prediction
        prediction = self.model.predict(X_combined)[0]
        prediction_proba = self.model.predict_proba(X_combined)[0]
        
        return {
            'prediction': int(prediction),
            'prediction_label': 'Phishing' if prediction == 1 else 'Legitimate',
            'phishing_probability': float(prediction_proba[1]),
            'legitimate_probability': float(prediction_proba[0]),
            'confidence': float(max(prediction_proba))
        }
    
    def _extract_single_email_features(self, sender: str, subject: str, body: str) -> List[float]:
        """Extract numerical features for a single email"""
        features = []
        
        # Length features
        features.append(len(subject))
        features.append(len(body))
        features.append(len(sender))
        
        # URL features
        url_count = len(re.findall(r'http[s]?://', body))
        features.append(url_count)
        features.append(1 if url_count > 0 else 0)
        
        # Urgency features
        urgency_keywords = ['urgent', 'immediate', 'asap', 'now', 'today', 'expires', 'deadline']
        has_urgency = 1 if any(keyword in subject.lower() for keyword in urgency_keywords) else 0
        features.append(has_urgency)
        
        # Suspicious domain features
        suspicious_domains = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']
        has_suspicious = 1 if any(domain in body.lower() for domain in suspicious_domains) else 0
        features.append(has_suspicious)
        
        # Authority spoofing
        authority_terms = ['microsoft', 'apple', 'amazon', 'paypal', 'google', 'bank']
        has_authority = 1 if any(term in sender.lower() for term in authority_terms) else 0
        features.append(has_authority)
        
        # Email pattern features
        features.append(1 if '-' in sender else 0)
        features.append(1 if re.search(r'\d', sender) else 0)
        
        # Caps ratio
        caps_ratio = sum(1 for c in subject if c.isupper()) / len(subject) if len(subject) > 0 else 0
        features.append(caps_ratio)
        
        return features
    
    def save_model(self):
        """Save the trained model and vectorizer"""
        model_file = self.model_path / "phishing_classifier.joblib"
        vectorizer_file = self.model_path / "tfidf_vectorizer.joblib"
        
        joblib.dump(self.model, model_file)
        joblib.dump(self.vectorizer, vectorizer_file)
        
        print(f"Model saved to: {model_file}")
        print(f"Vectorizer saved to: {vectorizer_file}")
    
    def load_model(self):
        """Load a previously trained model"""
        model_file = self.model_path / "phishing_classifier.joblib"
        vectorizer_file = self.model_path / "tfidf_vectorizer.joblib"
        
        if model_file.exists() and vectorizer_file.exists():
            self.model = joblib.load(model_file)
            self.vectorizer = joblib.load(vectorizer_file)
            print("Model and vectorizer loaded successfully!")
            return True
        else:
            print("No saved model found. Please train the model first.")
            return False

def test_ml_classifier():
    """Test the ML classifier"""
    classifier = PhishingMLClassifier()
    
    # Train the model
    print("Training ML classifier...")
    accuracy = classifier.train_model()
    
    # Test predictions
    print("\n" + "="*50)
    print("=== TESTING PREDICTIONS ===")
    
    # Test phishing email
    phishing_result = classifier.predict_email(
        sender="security@paypaI-alerts.com",
        subject="URGENT: Your account has been suspended",
        body="Your PayPal account has been suspended. Click here immediately to verify: http://fake-paypal.com"
    )
    
    print(f"\n🔴 PHISHING EMAIL TEST:")
    print(f"Prediction: {phishing_result['prediction_label']}")
    print(f"Phishing Probability: {phishing_result['phishing_probability']:.3f}")
    print(f"Confidence: {phishing_result['confidence']:.3f}")
    
    # Test legitimate email
    legitimate_result = classifier.predict_email(
        sender="hr@company.com",
        subject="Team meeting tomorrow",
        body="Hi everyone, just a reminder about our team meeting tomorrow at 2 PM in the conference room."
    )
    
    print(f"\n🟢 LEGITIMATE EMAIL TEST:")
    print(f"Prediction: {legitimate_result['prediction_label']}")
    print(f"Phishing Probability: {legitimate_result['phishing_probability']:.3f}")
    print(f"Confidence: {legitimate_result['confidence']:.3f}")

if __name__ == "__main__":
    test_ml_classifier()