"""
Integrated Phishing Detection System
Combines all AI components into a unified detection platform
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Import all our components
from email_parser import PhishingEmailParser, EmailFeatures
from nlp_analyzer import NLPAnalyzer
from ml_classifier import PhishingMLClassifier
from user_behavior import UserBehaviorAnalyzer
from llm_intelligence import LLMIntelligenceEngine

class IntegratedPhishingDetector:
    """Master phishing detection system combining all AI components"""
    
    def __init__(self, user_db_path: str = "data/user_behavior.db"):
        print("Initializing Integrated Phishing Detection System...")
        
        # Initialize all components
        self.email_parser = PhishingEmailParser()
        self.nlp_analyzer = NLPAnalyzer()
        self.ml_classifier = PhishingMLClassifier()
        self.behavior_analyzer = UserBehaviorAnalyzer(user_db_path)
        self.llm_intelligence = LLMIntelligenceEngine()
        
        # Load trained ML model
        if not self.ml_classifier.load_model():
            print("Training ML model...")
            self.ml_classifier.train_model()
        
        print("✅ All systems initialized and ready!")
    
    def analyze_email(self, user_id: str, email_content: str, 
                     interaction_type: str = "received") -> Dict:
        """
        Complete email analysis pipeline
        Returns comprehensive threat assessment
        """
        
        analysis_start = datetime.now()
        
        # Step 1: Parse email content
        print("🔍 Step 1: Parsing email content...")
        email_features = self.email_parser.parse_email_text(email_content)
        
        # Step 2: Advanced NLP analysis
        print("🧠 Step 2: Advanced NLP analysis...")
        full_text = f"{email_features.subject} {email_features.body_text}"
        nlp_results = self.nlp_analyzer.analyze_text(full_text)
        
        # Step 3: ML classification
        print("🤖 Step 3: Machine learning classification...")
        ml_prediction = self.ml_classifier.predict_email(
            email_features.sender_email,
            email_features.subject,
            email_features.body_text
        )
        
        # Step 4: Behavioral analysis
        print("👤 Step 4: User behavioral analysis...")
        current_hour = datetime.now().hour
        behavioral_analysis = self.behavior_analyzer.detect_anomalies(
            user_id,
            email_features.sender_email,
            email_features.subject,
            current_hour,
            ml_prediction['phishing_probability']
        )
        
        # Step 5: LLM threat intelligence
        print("🔬 Step 5: AI threat intelligence analysis...")
        
        # Convert email_features to dict for LLM
        email_features_dict = {
            'sender_email': email_features.sender_email,
            'subject': email_features.subject,
            'body_text': email_features.body_text,
            'urls': email_features.urls,
            'suspicious_keywords': email_features.suspicious_keywords,
            'sentiment_analysis': email_features.sentiment_analysis,
            'urgency_score': email_features.urgency_score,
            'authority_spoofing': email_features.authority_spoofing,
            'financial_context': email_features.financial_context
        }
        
        threat_intelligence = self.llm_intelligence.analyze_threat_intelligence(
            email_features_dict, ml_prediction, behavioral_analysis
        )
        
        # Step 6: Calculate final risk score
        print("⚡ Step 6: Calculating final risk assessment...")
        final_risk_assessment = self._calculate_final_risk_score(
            email_features, ml_prediction, behavioral_analysis, threat_intelligence
        )
        
        # Step 7: Generate recommendations
        print("📋 Step 7: Generating security recommendations...")
        security_recommendations = self._generate_security_recommendations(
            final_risk_assessment, threat_intelligence, behavioral_analysis
        )
        
        # Log the interaction
        self.behavior_analyzer.log_email_interaction(
            user_id,
            email_features.sender_email,
            email_features.subject,
            interaction_type,
            final_risk_assessment['final_score'],
            final_risk_assessment['is_phishing']
        )
        
        analysis_duration = (datetime.now() - analysis_start).total_seconds()
        
        # Compile comprehensive results
        comprehensive_analysis = {
            'analysis_metadata': {
                'analysis_id': self._generate_analysis_id(),
                'timestamp': analysis_start.isoformat(),
                'duration_seconds': analysis_duration,
                'user_id': user_id,
                'system_version': '1.0.0'
            },
            'email_analysis': {
                'basic_features': self._extract_basic_features_summary(email_features),
                'nlp_analysis': nlp_results,
                'ml_classification': ml_prediction,
                'behavioral_analysis': behavioral_analysis,
                'threat_intelligence': threat_intelligence
            },
            'risk_assessment': final_risk_assessment,
            'security_recommendations': security_recommendations,
            'generated_rules': self._generate_detection_rules(email_features_dict, threat_intelligence),
            'executive_summary': self._create_analysis_summary(final_risk_assessment, threat_intelligence)
        }
        
        print(f"✅ Analysis complete in {analysis_duration:.2f} seconds")
        return comprehensive_analysis
    
    def _calculate_final_risk_score(self, email_features: EmailFeatures, ml_prediction: Dict,
                                   behavioral_analysis: Dict, threat_intelligence: Dict) -> Dict:
        """Calculate weighted final risk score from all components"""
        
        # Individual component scores
        ml_score = ml_prediction['phishing_probability']
        behavioral_score = behavioral_analysis['anomaly_score']
        nlp_score = email_features.urgency_score
        
        # Threat intelligence factors
        threat_classification = threat_intelligence['threat_classification']
        sophistication = threat_intelligence['sophistication_level']
        business_impact = threat_intelligence['business_impact']
        
        # Weighted scoring (enterprise-grade)
        weights = {
            'ml_prediction': 0.35,        # ML is primary classifier
            'behavioral_anomaly': 0.25,   # User behavior is critical
            'threat_intelligence': 0.20,  # LLM analysis adds context
            'nlp_analysis': 0.20          # NLP provides linguistic insight
        }
        
        # Calculate threat intelligence score
        threat_intel_score = 0.0
        if threat_classification['primary_threat'] != 'unknown':
            threat_intel_score += 0.4
        
        threat_intel_score += sophistication['score'] * 0.3
        threat_intel_score += business_impact['score'] * 0.3
        
        # Calculate weighted final score
        final_score = (
            ml_score * weights['ml_prediction'] +
            behavioral_score * weights['behavioral_anomaly'] +
            threat_intel_score * weights['threat_intelligence'] +
            nlp_score * weights['nlp_analysis']
        )
        
        # Risk level classification
        if final_score >= 0.8:
            risk_level = 'CRITICAL'
            action = 'BLOCK'
        elif final_score >= 0.6:
            risk_level = 'HIGH'
            action = 'QUARANTINE'
        elif final_score >= 0.4:
            risk_level = 'MEDIUM'
            action = 'FLAG'
        elif final_score >= 0.2:
            risk_level = 'LOW'
            action = 'MONITOR'
        else:
            risk_level = 'MINIMAL'
            action = 'ALLOW'
        
        return {
            'final_score': final_score,
            'risk_level': risk_level,
            'recommended_action': action,
            'is_phishing': final_score >= 0.6,
            'confidence': max(ml_prediction['confidence'], 0.7),
            'component_scores': {
                'ml_prediction': ml_score,
                'behavioral_anomaly': behavioral_score,
                'threat_intelligence': threat_intel_score,
                'nlp_analysis': nlp_score
            },
            'reasoning': self._generate_risk_reasoning(final_score, threat_classification, sophistication)
        }
    
    def _generate_security_recommendations(self, risk_assessment: Dict, 
                                         threat_intelligence: Dict, 
                                         behavioral_analysis: Dict) -> List[Dict]:
        """Generate comprehensive security recommendations"""
        
        recommendations = []
        
        # Critical risk actions
        if risk_assessment['risk_level'] == 'CRITICAL':
            recommendations.append({
                'priority': 'IMMEDIATE',
                'action': 'Block and Isolate',
                'description': 'Immediately block sender and quarantine all similar emails',
                'implementation': f"Add {threat_intelligence.get('ioc_extraction', {}).get('domains', ['unknown'])[0] if threat_intelligence.get('ioc_extraction', {}).get('domains') else 'sender domain'} to email gateway blacklist",
                'timeline': 'Within 5 minutes'
            })
        
        # High risk actions
        if risk_assessment['risk_level'] in ['CRITICAL', 'HIGH']:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'User Training',
                'description': 'Provide immediate security awareness training to affected user',
                'implementation': 'Enroll user in targeted phishing simulation and training program',
                'timeline': 'Within 24 hours'
            })
        
        # Behavioral anomaly actions
        if behavioral_analysis['anomaly_score'] > 0.7:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Enhanced Monitoring',
                'description': 'Increase monitoring for this user due to behavioral anomalies',
                'implementation': 'Add user to high-risk monitoring list for 30 days',
                'timeline': 'Within 2 hours'
            })
        
        # Technical controls
        iocs = threat_intelligence.get('ioc_extraction', {})
        if iocs.get('urls'):
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'URL Analysis',
                'description': 'Analyze and potentially block suspicious URLs',
                'implementation': f"Submit URLs to threat intelligence platform: {', '.join(iocs['urls'][:3])}",
                'timeline': 'Within 1 hour'
            })
        
        # MITRE ATT&CK based recommendations
        mitre_techniques = threat_intelligence.get('mitre_mapping', {}).get('techniques', [])
        if mitre_techniques:
            recommendations.append({
                'priority': 'LOW',
                'action': 'Update Detection Rules',
                'description': f"Update SIEM rules for detected MITRE techniques: {', '.join([t['technique_id'] for t in mitre_techniques[:2]])}",
                'implementation': 'Deploy generated detection rules to SIEM platform',
                'timeline': 'Within 8 hours'
            })
        
        return recommendations
    
    def _generate_detection_rules(self, email_features: Dict, threat_intelligence: Dict) -> List[Dict]:
        """Generate detection rules for SOC deployment"""
        
        rules = []
        
        # Generate rule based on primary threat type
        primary_threat = threat_intelligence['threat_classification']['primary_threat']
        rule = self.llm_intelligence.generate_detection_rule(email_features, primary_threat)
        rules.append(rule)
        
        # Generate behavioral rule if needed
        if threat_intelligence['business_impact']['level'] in ['critical', 'high']:
            behavioral_rule = {
                'name': f"behavioral_anomaly_{primary_threat}",
                'description': f'Detects behavioral anomalies associated with {primary_threat}',
                'pattern': 'user_behavior_anomaly AND high_risk_email',
                'confidence': 0.75,
                'rule_type': 'behavioral_analysis',
                'metadata': {
                    'generated_by': 'Behavioral Analysis Engine',
                    'created_date': datetime.now().isoformat(),
                    'rule_id': self.llm_intelligence._generate_rule_id(f"behavioral_{primary_threat}")
                }
            }
            rules.append(behavioral_rule)
        
        return rules
    
    def _extract_basic_features_summary(self, email_features: EmailFeatures) -> Dict:
        """Extract basic features summary"""
        return {
            'sender': email_features.sender_email,
            'subject': email_features.subject[:100] + "..." if len(email_features.subject) > 100 else email_features.subject,
            'body_length': len(email_features.body_text),
            'url_count': len(email_features.urls),
            'suspicious_keyword_count': len(email_features.suspicious_keywords),
            'has_attachments': False,  # Would be implemented with attachment analysis
            'timestamp_analyzed': datetime.now().isoformat()
        }
    
    def _generate_analysis_id(self) -> str:
        """Generate unique analysis ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        import hashlib
        import random
        random_hash = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
        return f"ANALYSIS_{timestamp}_{random_hash}"
    
    def _generate_risk_reasoning(self, final_score: float, threat_classification: Dict, 
                               sophistication: Dict) -> str:
        """Generate human-readable risk reasoning"""
        
        reasoning_parts = []
        
        if final_score >= 0.8:
            reasoning_parts.append("CRITICAL THREAT DETECTED")
        elif final_score >= 0.6:
            reasoning_parts.append("HIGH RISK EMAIL")
        elif final_score >= 0.4:
            reasoning_parts.append("MEDIUM RISK EMAIL")
        else:
            reasoning_parts.append("LOW RISK EMAIL")
        
        # Add threat type
        primary_threat = threat_classification.get('primary_threat', 'unknown')
        if primary_threat != 'unknown':
            reasoning_parts.append(f"Primary threat: {primary_threat.replace('_', ' ').title()}")
        
        # Add sophistication
        soph_level = sophistication.get('level', 'unknown')
        if soph_level != 'unknown':
            reasoning_parts.append(f"Sophistication: {soph_level.title()}")
        
        return " | ".join(reasoning_parts)
    
    def _create_analysis_summary(self, risk_assessment: Dict, threat_intelligence: Dict) -> str:
        """Create executive analysis summary"""
        
        risk_level = risk_assessment['risk_level']
        primary_threat = threat_intelligence['threat_classification']['primary_threat']
        business_impact = threat_intelligence['business_impact']['level']
        
        summary = f"""
PHISHING DETECTION ANALYSIS SUMMARY
===================================
Risk Level: {risk_level}
Recommended Action: {risk_assessment['recommended_action']}
Primary Threat Type: {primary_threat.replace('_', ' ').title()}
Business Impact: {business_impact.upper()}

Key Findings:
- Final Risk Score: {risk_assessment['final_score']:.2f}/1.0
- ML Classification Confidence: {risk_assessment['confidence']:.2f}
- Threat Sophistication: {threat_intelligence['sophistication_level']['level'].title()}

Risk Reasoning: {risk_assessment['reasoning']}

MITRE ATT&CK Techniques:
{chr(10).join([f"- {t['technique_id']}: {t['technique_name']}" for t in threat_intelligence['mitre_mapping']['techniques'][:3]])}
"""
        return summary

def test_integrated_detector():
    """Test the complete integrated detection system"""
    
    detector = IntegratedPhishingDetector()
    
    # Create test user
    user_id = detector.behavior_analyzer.create_user("test_analyst", "analyst@company.com")
    
    # Test phishing email
    phishing_email = """From: security-team@microsooft-alerts.com
Subject: URGENT: Your Microsoft account will be deleted in 24 hours
To: analyst@company.com

Dear Microsoft User,

We are the Microsoft Security Team. Your account has been SUSPENDED due to suspicious activity detected from your IP address.

IMMEDIATE ACTION REQUIRED:
- Your account will be permanently deleted in 24 hours
- All your files and emails will be lost forever
- You must verify your identity NOW to prevent deletion

Click here to verify and save your account: http://microsoft-security-verify.suspicious-domain.com/urgent-verify-now

This is your FINAL WARNING. Do not ignore this critical security alert.

Time remaining: 23 hours, 47 minutes

Microsoft Security Department
Do not reply to this email
"""
    
    print("="*60)
    print("🚀 TESTING INTEGRATED PHISHING DETECTION SYSTEM")
    print("="*60)
    
    # Run complete analysis
    analysis_results = detector.analyze_email(user_id, phishing_email)
    
    # Display key results
    print(f"\n📊 ANALYSIS RESULTS:")
    print(f"Analysis ID: {analysis_results['analysis_metadata']['analysis_id']}")
    print(f"Duration: {analysis_results['analysis_metadata']['duration_seconds']:.2f} seconds")
    
    print(f"\n🎯 RISK ASSESSMENT:")
    risk = analysis_results['risk_assessment']
    print(f"Final Risk Score: {risk['final_score']:.2f}/1.0")
    print(f"Risk Level: {risk['risk_level']}")
    print(f"Recommended Action: {risk['recommended_action']}")
    print(f"Is Phishing: {risk['is_phishing']}")
    print(f"Reasoning: {risk['reasoning']}")
    
    print(f"\n🔍 COMPONENT SCORES:")
    for component, score in risk['component_scores'].items():
        print(f"  {component}: {score:.2f}")
    
    print(f"\n📋 SECURITY RECOMMENDATIONS:")
    for i, rec in enumerate(analysis_results['security_recommendations'], 1):
        print(f"{i}. {rec['action']} ({rec['priority']})")
        print(f"   {rec['description']}")
        print(f"   Timeline: {rec['timeline']}")
    
    print(f"\n⚙️ GENERATED DETECTION RULES:")
    for rule in analysis_results['generated_rules']:
        print(f"  Rule: {rule['name']} (Confidence: {rule['confidence']})")
    
    print(f"\n📄 EXECUTIVE SUMMARY:")
    print(analysis_results['executive_summary'])
    
    print("\n" + "="*60)
    print("✅ INTEGRATED SYSTEM TEST COMPLETED SUCCESSFULLY!")
    print("="*60)

if __name__ == "__main__":
    test_integrated_detector()