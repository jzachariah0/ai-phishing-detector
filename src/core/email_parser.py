"""
AI-Driven Phishing Email Detector - Enhanced Email Parser
Email parsing with advanced NLP analysis integration
"""

import re
import email
from typing import Dict, List
from nlp_analyzer import NLPAnalyzer

class EmailFeatures:
    """Stores extracted email features with advanced NLP analysis"""
    
    def __init__(self):
        # Basic email properties
        self.sender_email = ""
        self.subject = ""
        self.body_text = ""
        self.urls = []
        self.suspicious_keywords = []
        
        # Advanced NLP features
        self.sentiment_analysis = {}
        self.urgency_score = 0.0
        self.linguistic_features = {}
        self.authority_spoofing = {}
        self.financial_context = {}
        self.readability = {}
        self.advanced_risk_score = 0.0

class PhishingEmailParser:
    """Enhanced email parser with NLP analysis"""
    
    def __init__(self):
        self.phishing_keywords = [
            "urgent", "verify account", "click here", "suspended",
            "confirm identity", "update payment", "security alert"
        ]
        
        self.url_pattern = re.compile(r'http[s]?://[^\s<>"]+')
        
        # Initialize NLP analyzer
        self.nlp_analyzer = NLPAnalyzer()
    
    def parse_email_text(self, email_content: str) -> EmailFeatures:
        """Parse email with advanced NLP analysis"""
        features = EmailFeatures()
        
        # Parse basic email structure
        email_obj = email.message_from_string(email_content)
        
        features.sender_email = email_obj.get('From', '')
        features.subject = email_obj.get('Subject', '')
        
        # Get email body
        if email_obj.is_multipart():
            for part in email_obj.walk():
                if part.get_content_type() == "text/plain":
                    features.body_text = part.get_payload()
        else:
            features.body_text = email_obj.get_payload()
        
        # Extract URLs
        all_text = f"{features.subject} {features.body_text}"
        features.urls = self.url_pattern.findall(all_text)
        
        # Check for basic suspicious keywords
        text_lower = all_text.lower()
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                features.suspicious_keywords.append(keyword)
        
        # NEW: Advanced NLP Analysis
        self._perform_nlp_analysis(features, all_text)
        
        # Calculate enhanced risk score
        features.advanced_risk_score = self._calculate_advanced_risk_score(features)
        
        return features
    
    def _perform_nlp_analysis(self, features: EmailFeatures, text: str):
        """Perform comprehensive NLP analysis"""
        nlp_results = self.nlp_analyzer.analyze_text(text)
        
        # Store all NLP results in features
        features.sentiment_analysis = nlp_results['sentiment']
        features.urgency_score = nlp_results['urgency_score']
        features.linguistic_features = nlp_results['linguistic_features']
        features.authority_spoofing = nlp_results['authority_spoofing']
        features.financial_context = nlp_results['financial_context']
        features.readability = nlp_results['readability']
    
    def _calculate_advanced_risk_score(self, features: EmailFeatures) -> float:
        """Calculate sophisticated risk score using all features"""
        risk_score = 0.0
        
        # Basic suspicious keywords (original scoring)
        risk_score += len(features.suspicious_keywords) * 0.15
        
        # Multiple URLs
        if len(features.urls) > 2:
            risk_score += 0.2
        
        # NEW: NLP-based scoring
        
        # Negative sentiment increases risk
        if features.sentiment_analysis.get('is_negative', False):
            risk_score += 0.2
        
        # High urgency is very suspicious
        risk_score += features.urgency_score * 0.3
        
        # Authority spoofing is major red flag
        if features.authority_spoofing.get('likely_spoofing', False):
            risk_score += 0.4
        
        # Financial context + urgency = phishing
        if features.financial_context.get('has_financial_context', False):
            risk_score += 0.2
            if features.urgency_score > 0.5:  # Financial + urgent = very suspicious
                risk_score += 0.3
        
        # Highly emotional content is suspicious
        if features.sentiment_analysis.get('is_highly_emotional', False):
            risk_score += 0.15
        
        # Cap at 1.0
        return min(risk_score, 1.0)
    
    def get_detailed_analysis(self, features: EmailFeatures) -> Dict:
        """Get human-readable analysis report"""
        return {
            'basic_info': {
                'sender': features.sender_email,
                'subject': features.subject[:50] + "..." if len(features.subject) > 50 else features.subject,
                'url_count': len(features.urls),
                'suspicious_keywords': features.suspicious_keywords
            },
            'sentiment': {
                'emotional_tone': 'Negative' if features.sentiment_analysis.get('is_negative') else 'Neutral/Positive',
                'polarity_score': features.sentiment_analysis.get('polarity', 0),
                'highly_emotional': features.sentiment_analysis.get('is_highly_emotional', False)
            },
            'threat_indicators': {
                'urgency_level': 'High' if features.urgency_score > 0.7 else 'Medium' if features.urgency_score > 0.3 else 'Low',
                'authority_spoofing': features.authority_spoofing.get('likely_spoofing', False),
                'impersonated_entities': features.authority_spoofing.get('authority_references', []),
                'financial_context': features.financial_context.get('has_financial_context', False)
            },
            'risk_assessment': {
                'basic_risk_score': min(len(features.suspicious_keywords) * 0.2 + (0.3 if len(features.urls) > 2 else 0), 1.0),
                'advanced_risk_score': features.advanced_risk_score,
                'risk_level': self._get_risk_level(features.advanced_risk_score),
                'recommendation': self._get_recommendation(features.advanced_risk_score)
            }
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to human-readable level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_recommendation(self, score: float) -> str:
        """Get action recommendation based on risk score"""
        if score >= 0.8:
            return "BLOCK - High probability phishing attempt"
        elif score >= 0.6:
            return "QUARANTINE - Manual review required"
        elif score >= 0.4:
            return "FLAG - Monitor and warn user"
        elif score >= 0.2:
            return "CAUTION - Low risk but monitor"
        else:
            return "ALLOW - Appears legitimate"

# Enhanced test function
def test_enhanced_parser():
    """Test the enhanced email parser"""
    parser = PhishingEmailParser()
    
    # Test sophisticated phishing email
    phishing_email = """From: security-alerts@microsooft-team.com
Subject: URGENT: Your Microsoft account will be deleted in 24 hours!
To: victim@example.com

Dear Valued Customer,

We are Microsoft Security Team. Your account has been SUSPENDED due to suspicious activity detected from your location.

IMMEDIATE ACTION REQUIRED:
- Your account will be permanently deleted in 24 hours
- All your files will be lost forever
- Click here to verify now: http://fake-microsoft-verify.suspicious.com/urgent-verify

This is your FINAL WARNING. Do not ignore this message.

Time remaining: 23 hours, 45 minutes

Microsoft Security Department
"""
    
    print("=== ENHANCED PHISHING ANALYSIS ===")
    features = parser.parse_email_text(phishing_email)
    detailed_analysis = parser.get_detailed_analysis(features)
    
    print(f"\n📧 BASIC INFO:")
    print(f"Sender: {detailed_analysis['basic_info']['sender']}")
    print(f"Subject: {detailed_analysis['basic_info']['subject']}")
    print(f"URLs: {detailed_analysis['basic_info']['url_count']}")
    print(f"Suspicious Keywords: {detailed_analysis['basic_info']['suspicious_keywords']}")
    
    print(f"\n🧠 SENTIMENT ANALYSIS:")
    print(f"Emotional Tone: {detailed_analysis['sentiment']['emotional_tone']}")
    print(f"Highly Emotional: {detailed_analysis['sentiment']['highly_emotional']}")
    
    print(f"\n⚠️  THREAT INDICATORS:")
    print(f"Urgency Level: {detailed_analysis['threat_indicators']['urgency_level']}")
    print(f"Authority Spoofing: {detailed_analysis['threat_indicators']['authority_spoofing']}")
    print(f"Impersonated: {detailed_analysis['threat_indicators']['impersonated_entities']}")
    print(f"Financial Context: {detailed_analysis['threat_indicators']['financial_context']}")
    
    print(f"\n🎯 RISK ASSESSMENT:")
    print(f"Basic Risk Score: {detailed_analysis['risk_assessment']['basic_risk_score']:.2f}")
    print(f"Advanced Risk Score: {detailed_analysis['risk_assessment']['advanced_risk_score']:.2f}")
    print(f"Risk Level: {detailed_analysis['risk_assessment']['risk_level']}")
    print(f"Recommendation: {detailed_analysis['risk_assessment']['recommendation']}")
    
    # Test legitimate email for comparison
    print("\n" + "="*50)
    print("=== LEGITIMATE EMAIL ANALYSIS ===")
    
    legitimate_email = """From: hr@company.com
Subject: Team Building Event Next Friday
To: employee@company.com

Hi Team,

Hope everyone is doing well! 

I wanted to remind you about our team building event next Friday at 3 PM in the main conference room. We'll have some fun activities and refreshments.

Please let me know if you can attend by replying to this email.

Thanks!
Sarah
HR Department
"""
    
    legitimate_features = parser.parse_email_text(legitimate_email)
    legitimate_analysis = parser.get_detailed_analysis(legitimate_features)
    
    print(f"\n📧 BASIC INFO:")
    print(f"Sender: {legitimate_analysis['basic_info']['sender']}")
    print(f"Subject: {legitimate_analysis['basic_info']['subject']}")
    
    print(f"\n🎯 RISK ASSESSMENT:")
    print(f"Advanced Risk Score: {legitimate_analysis['risk_assessment']['advanced_risk_score']:.2f}")
    print(f"Risk Level: {legitimate_analysis['risk_assessment']['risk_level']}")
    print(f"Recommendation: {legitimate_analysis['risk_assessment']['recommendation']}")

if __name__ == "__main__":
    test_enhanced_parser()