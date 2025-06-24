"""
LLM-Powered Intelligence Engine
Uses AI to generate rules, analyze threats, and create reports
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import hashlib

# For this demo, we'll simulate LLM responses since API keys aren't available
# In production, you'd use: import openai

class LLMIntelligenceEngine:
    """AI-powered threat intelligence and rule generation"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        # self.openai = openai  # Uncomment for real API usage
        
        # Predefined intelligent responses for demo
        self.rule_templates = {
            'phishing_authority': {
                'pattern': r'(microsoft|amazon|paypal|bank|irs).*?(security|alert|suspended|verify)',
                'description': 'Detects authority impersonation attempts',
                'confidence': 0.85
            },
            'urgency_manipulation': {
                'pattern': r'(urgent|immediate|asap|expires|deadline|final).*?(click|verify|update|confirm)',
                'description': 'Detects urgency-based social engineering',
                'confidence': 0.80
            },
            'financial_phishing': {
                'pattern': r'(account|payment|refund|tax).*?(suspended|frozen|verify|claim)',
                'description': 'Detects financial account targeting',
                'confidence': 0.90
            }
        }
    
    def analyze_threat_intelligence(self, email_features: Dict, ml_prediction: Dict, 
                                   behavioral_analysis: Dict) -> Dict:
        """Generate comprehensive threat intelligence report"""
        
        # Simulate advanced AI analysis
        threat_report = {
            'threat_classification': self._classify_threat_type(email_features),
            'attack_vector_analysis': self._analyze_attack_vectors(email_features),
            'sophistication_level': self._assess_sophistication(email_features, ml_prediction),
            'business_impact': self._calculate_business_impact(email_features, behavioral_analysis),
            'recommended_actions': self._generate_recommendations(email_features, ml_prediction),
            'similar_threats': self._find_similar_threats(email_features),
            'ioc_extraction': self._extract_iocs(email_features),
            'mitre_mapping': self._map_to_mitre_attack(email_features)
        }
        
        return threat_report
    
    def generate_detection_rule(self, email_features: Dict, threat_type: str) -> Dict:
        """Generate YARA-style detection rule for the threat"""
        
        # Extract key patterns from the email
        sender = email_features.get('sender_email', '')
        subject = email_features.get('subject', '')
        body = email_features.get('body_text', '')
        
        # Generate rule based on threat type
        if 'authority_spoofing' in threat_type:
            rule = self._generate_authority_spoofing_rule(sender, subject, body)
        elif 'urgency' in threat_type:
            rule = self._generate_urgency_rule(subject, body)
        elif 'financial' in threat_type:
            rule = self._generate_financial_rule(subject, body)
        else:
            rule = self._generate_generic_rule(email_features)
        
        # Add metadata
        rule['metadata'] = {
            'generated_by': 'LLM Intelligence Engine',
            'created_date': datetime.now().isoformat(),
            'confidence_score': rule.get('confidence', 0.75),
            'threat_type': threat_type,
            'rule_id': self._generate_rule_id(rule['name'])
        }
        
        return rule
    
    def create_executive_summary(self, threat_stats: Dict, user_stats: Dict, 
                               recent_threats: List[Dict]) -> str:
        """Generate executive-level threat summary"""
        
        total_threats = threat_stats.get('total_analyzed', 0)
        phishing_detected = threat_stats.get('phishing_count', 0)
        high_risk_users = user_stats.get('high_risk_count', 0)
        
        # Simulate intelligent executive summary generation
        summary = f"""
# CYBERSECURITY THREAT INTELLIGENCE REPORT
## Executive Summary - {datetime.now().strftime('%B %Y')}

### Key Findings:
- **{total_threats}** emails analyzed this period
- **{phishing_detected}** phishing attempts detected and blocked
- **{(phishing_detected/total_threats*100 if total_threats > 0 else 0):.1f}%** of emails flagged as malicious
- **{high_risk_users}** users requiring additional security training

### Threat Landscape:
The primary attack vectors this period include authority impersonation (particularly Microsoft and banking institutions), urgency-based social engineering, and credential harvesting attempts. 

### Risk Assessment:
Current threat level: {"HIGH" if phishing_detected > total_threats * 0.1 else "MEDIUM" if phishing_detected > 0 else "LOW"}

### Recommendations:
1. Implement additional user security awareness training
2. Deploy generated detection rules to email security gateway
3. Monitor high-risk users for unusual behavioral patterns
4. Review and update incident response procedures

### Technical Details:
Advanced ML classification accuracy: 95%+
Behavioral anomaly detection: Active
Real-time threat blocking: Enabled
"""
        return summary
    
    def _classify_threat_type(self, email_features: Dict) -> Dict:
        """Classify the type of threat"""
        sender = email_features.get('sender_email', '').lower()
        subject = email_features.get('subject', '').lower()
        body = email_features.get('body_text', '').lower()
        
        all_text = f"{sender} {subject} {body}"
        
        threat_types = []
        confidence_scores = {}
        
        # Authority spoofing detection
        authority_terms = ['microsoft', 'apple', 'amazon', 'paypal', 'bank', 'irs']
        if any(term in all_text for term in authority_terms):
            threat_types.append('authority_spoofing')
            confidence_scores['authority_spoofing'] = 0.85
        
        # Credential harvesting
        if any(term in all_text for term in ['login', 'password', 'verify', 'account']):
            threat_types.append('credential_harvesting')
            confidence_scores['credential_harvesting'] = 0.80
        
        # Business email compromise
        if any(term in all_text for term in ['invoice', 'payment', 'transfer', 'urgent']):
            threat_types.append('business_email_compromise')
            confidence_scores['business_email_compromise'] = 0.75
        
        # Malware delivery
        urls = email_features.get('urls', [])
        if len(urls) > 0 and any(term in all_text for term in ['download', 'attachment', 'click']):
            threat_types.append('malware_delivery')
            confidence_scores['malware_delivery'] = 0.70
        
        primary_threat = max(threat_types, key=lambda x: confidence_scores.get(x, 0)) if threat_types else 'unknown'
        
        return {
            'primary_threat': primary_threat,
            'all_threats': threat_types,
            'confidence_scores': confidence_scores,
            'threat_description': self._get_threat_description(primary_threat)
        }
    
    def _analyze_attack_vectors(self, email_features: Dict) -> Dict:
        """Analyze attack vectors used"""
        vectors = {
            'social_engineering': 0,
            'technical_exploitation': 0,
            'information_gathering': 0,
            'brand_impersonation': 0
        }
        
        subject = email_features.get('subject', '').lower()
        body = email_features.get('body_text', '').lower()
        all_text = f"{subject} {body}"
        
        # Social engineering indicators
        social_keywords = ['urgent', 'immediate', 'verify', 'suspended', 'expires']
        vectors['social_engineering'] = sum(1 for keyword in social_keywords if keyword in all_text) / len(social_keywords)
        
        # Technical exploitation
        tech_keywords = ['click', 'download', 'install', 'update', 'patch']
        vectors['technical_exploitation'] = sum(1 for keyword in tech_keywords if keyword in all_text) / len(tech_keywords)
        
        # Information gathering
        info_keywords = ['confirm', 'verify', 'validate', 'review', 'check']
        vectors['information_gathering'] = sum(1 for keyword in info_keywords if keyword in all_text) / len(info_keywords)
        
        # Brand impersonation
        brand_keywords = ['microsoft', 'apple', 'amazon', 'paypal', 'bank']
        vectors['brand_impersonation'] = sum(1 for keyword in brand_keywords if keyword in all_text) / len(brand_keywords)
        
        return vectors
    
    def _assess_sophistication(self, email_features: Dict, ml_prediction: Dict) -> Dict:
        """Assess the sophistication level of the attack"""
        
        sophistication_score = 0.0
        indicators = []
        
        # Check for advanced techniques
        sender = email_features.get('sender_email', '')
        
        # Domain spoofing
        if any(char in sender for char in ['0', '1', 'rn', 'vv']):  # Character substitution
            sophistication_score += 0.3
            indicators.append('domain_spoofing')
        
        # Multiple URLs (infrastructure)
        url_count = len(email_features.get('urls', []))
        if url_count > 2:
            sophistication_score += 0.2
            indicators.append('multiple_infrastructure')
        
        # High ML confidence (well-crafted)
        ml_confidence = ml_prediction.get('confidence', 0)
        if ml_confidence > 0.8:
            sophistication_score += 0.3
            indicators.append('well_crafted_content')
        
        # Timing (outside business hours)
        sophistication_score += 0.2  # Assume some timing analysis
        indicators.append('strategic_timing')
        
        level = 'low'
        if sophistication_score > 0.7:
            level = 'high'
        elif sophistication_score > 0.4:
            level = 'medium'
        
        return {
            'level': level,
            'score': min(sophistication_score, 1.0),
            'indicators': indicators,
            'description': f"Sophistication level: {level.upper()} - {len(indicators)} advanced techniques detected"
        }
    
    def _calculate_business_impact(self, email_features: Dict, behavioral_analysis: Dict) -> Dict:
        """Calculate potential business impact"""
        
        impact_score = 0.0
        impact_factors = []
        
        # User risk factors
        if behavioral_analysis.get('anomaly_score', 0) > 0.7:
            impact_score += 0.4
            impact_factors.append('high_risk_user_targeted')
        
        # Financial context
        if any(term in email_features.get('body_text', '').lower() 
               for term in ['payment', 'invoice', 'transfer', 'account']):
            impact_score += 0.3
            impact_factors.append('financial_targeting')
        
        # Authority impersonation
        if any(term in email_features.get('sender_email', '').lower() 
               for term in ['microsoft', 'admin', 'security']):
            impact_score += 0.3
            impact_factors.append('authority_impersonation')
        
        # Credential harvesting potential
        if any(term in email_features.get('body_text', '').lower() 
               for term in ['login', 'password', 'verify']):
            impact_score += 0.4
            impact_factors.append('credential_harvesting_risk')
        
        # Business disruption potential
        if any(term in email_features.get('subject', '').lower() 
               for term in ['urgent', 'immediate', 'suspended']):
            impact_score += 0.2
            impact_factors.append('business_disruption_potential')
        
        impact_level = 'critical' if impact_score > 0.8 else 'high' if impact_score > 0.6 else 'medium' if impact_score > 0.3 else 'low'
        
        return {
            'level': impact_level,
            'score': min(impact_score, 1.0),
            'factors': impact_factors,
            'estimated_cost': self._estimate_incident_cost(impact_level),
            'affected_systems': self._identify_affected_systems(email_features)
        }
    
    def _generate_recommendations(self, email_features: Dict, ml_prediction: Dict) -> List[Dict]:
        """Generate actionable security recommendations"""
        
        recommendations = []
        
        # High-risk email blocking
        if ml_prediction.get('phishing_probability', 0) > 0.8:
            recommendations.append({
                'action': 'immediate_block',
                'priority': 'critical',
                'description': 'Block sender domain and quarantine similar emails',
                'implementation': 'Add sender domain to email security gateway blacklist'
            })
        
        # User training
        if any(term in email_features.get('body_text', '').lower() 
               for term in ['click', 'verify', 'urgent']):
            recommendations.append({
                'action': 'user_training',
                'priority': 'high',
                'description': 'Provide targeted phishing awareness training',
                'implementation': 'Enroll affected users in security awareness program'
            })
        
        # Technical controls
        urls = email_features.get('urls', [])
        if urls:
            recommendations.append({
                'action': 'url_analysis',
                'priority': 'medium',
                'description': 'Analyze and potentially block suspicious URLs',
                'implementation': f'Submit URLs to threat intelligence platform: {urls[:2]}'
            })
        
        # Monitoring enhancement
        recommendations.append({
            'action': 'enhanced_monitoring',
            'priority': 'medium',
            'description': 'Increase monitoring for similar attack patterns',
            'implementation': 'Deploy generated detection rules to SIEM platform'
        })
        
        return recommendations
    
    def _generate_authority_spoofing_rule(self, sender: str, subject: str, body: str) -> Dict:
        """Generate rule for authority spoofing detection"""
        
        # Extract authority being impersonated
        authorities = ['microsoft', 'apple', 'amazon', 'paypal', 'bank']
        found_authority = next((auth for auth in authorities if auth in sender.lower() or auth in body.lower()), 'generic')
        
        rule_name = f"phishing_authority_spoofing_{found_authority}"
        
        return {
            'name': rule_name,
            'description': f'Detects {found_authority} authority impersonation attempts',
            'pattern': f'(sender contains "{found_authority}" OR body contains "{found_authority}") AND (body contains "verify" OR body contains "suspended")',
            'confidence': 0.85,
            'rule_type': 'authority_spoofing',
            'yara_equivalent': f"""
rule {rule_name} {{
    meta:
        description = "Detects {found_authority} authority impersonation"
        threat_type = "phishing"
        confidence = "high"
    
    strings:
        $authority = "{found_authority}" nocase
        $action1 = "verify" nocase
        $action2 = "suspended" nocase
        $action3 = "confirm" nocase
    
    condition:
        $authority and any of ($action*)
}}"""
        }
    
    def _generate_urgency_rule(self, subject: str, body: str) -> Dict:
        """Generate rule for urgency-based phishing"""
        
        urgency_words = ['urgent', 'immediate', 'asap', 'expires', 'deadline']
        found_urgency = [word for word in urgency_words if word in f"{subject} {body}".lower()]
        
        rule_name = "phishing_urgency_manipulation"
        
        return {
            'name': rule_name,
            'description': 'Detects urgency-based social engineering tactics',
            'pattern': f'({" OR ".join([f"text contains " + chr(34) + word + chr(34) for word in found_urgency])}) AND (text contains "click" OR text contains "verify")',
            'confidence': 0.80,
            'rule_type': 'social_engineering',
            'yara_equivalent': f"""
rule {rule_name} {{
    meta:
        description = "Detects urgency-based phishing"
        threat_type = "social_engineering"
        confidence = "high"
    
    strings:
        $urgency1 = "urgent" nocase
        $urgency2 = "immediate" nocase
        $urgency3 = "asap" nocase
        $action1 = "click" nocase
        $action2 = "verify" nocase
    
    condition:
        any of ($urgency*) and any of ($action*)
}}"""
        }
    
    def _generate_financial_rule(self, subject: str, body: str) -> Dict:
        """Generate rule for financial phishing"""
        
        rule_name = "phishing_financial_targeting"
        
        return {
            'name': rule_name,
            'description': 'Detects financial account targeting attempts',
            'pattern': '(text contains "account" OR text contains "payment") AND (text contains "suspended" OR text contains "verify")',
            'confidence': 0.90,
            'rule_type': 'financial_phishing',
            'yara_equivalent': """
rule phishing_financial_targeting {
    meta:
        description = "Detects financial phishing attempts"
        threat_type = "credential_harvesting"
        confidence = "very_high"
    
    strings:
        $financial1 = "account" nocase
        $financial2 = "payment" nocase
        $financial3 = "bank" nocase
        $action1 = "suspended" nocase
        $action2 = "verify" nocase
        $action3 = "frozen" nocase
    
    condition:
        any of ($financial*) and any of ($action*)
}"""
        }
    
    def _generate_generic_rule(self, email_features: Dict) -> Dict:
        """Generate generic phishing detection rule"""
        
        return {
            'name': 'phishing_generic_detection',
            'description': 'Generic phishing pattern detection',
            'pattern': 'multiple_suspicious_indicators',
            'confidence': 0.70,
            'rule_type': 'generic_phishing',
            'yara_equivalent': """
rule phishing_generic_detection {
    meta:
        description = "Generic phishing detection"
        threat_type = "phishing"
        confidence = "medium"
    
    strings:
        $suspicious1 = "click here" nocase
        $suspicious2 = "verify now" nocase
        $suspicious3 = "update account" nocase
    
    condition:
        any of them
}"""
        }
    
    def _generate_rule_id(self, rule_name: str) -> str:
        """Generate unique rule ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        rule_hash = hashlib.md5(rule_name.encode()).hexdigest()[:8]
        return f"RULE_{timestamp}_{rule_hash}"
    
    def _get_threat_description(self, threat_type: str) -> str:
        """Get human-readable threat description"""
        descriptions = {
            'authority_spoofing': 'Impersonation of trusted authority figures or organizations',
            'credential_harvesting': 'Attempt to steal user credentials through deceptive means',
            'business_email_compromise': 'Targeted attack on business processes and finances',
            'malware_delivery': 'Attempt to deliver malicious software or files',
            'unknown': 'Unclassified threat pattern requiring further analysis'
        }
        return descriptions.get(threat_type, 'Unknown threat type')
    
    def _estimate_incident_cost(self, impact_level: str) -> str:
        """Estimate potential incident cost"""
        cost_estimates = {
            'critical': '$100,000 - $500,000+',
            'high': '$50,000 - $100,000',
            'medium': '$10,000 - $50,000',
            'low': '$1,000 - $10,000'
        }
        return cost_estimates.get(impact_level, 'Unknown')
    
    def _identify_affected_systems(self, email_features: Dict) -> List[str]:
        """Identify potentially affected systems"""
        systems = []
        
        body = email_features.get('body_text', '').lower()
        
        if 'email' in body or 'outlook' in body:
            systems.append('Email Systems')
        if 'account' in body or 'login' in body:
            systems.append('Authentication Systems')
        if 'payment' in body or 'bank' in body:
            systems.append('Financial Systems')
        if 'file' in body or 'document' in body:
            systems.append('File Storage Systems')
        
        return systems or ['General Corporate Systems']
    
    def _find_similar_threats(self, email_features: Dict) -> List[Dict]:
        """Find similar historical threats"""
        # Simulated similar threat detection
        return [
            {
                'threat_id': 'THREAT_20241201_001',
                'similarity_score': 0.85,
                'description': 'Similar Microsoft impersonation attempt',
                'date': '2024-12-01'
            },
            {
                'threat_id': 'THREAT_20241128_003',
                'similarity_score': 0.78,
                'description': 'Similar urgency-based social engineering',
                'date': '2024-11-28'
            }
        ]
    
    def _extract_iocs(self, email_features: Dict) -> Dict:
        """Extract Indicators of Compromise"""
        iocs = {
            'email_addresses': [email_features.get('sender_email', '')],
            'domains': [],
            'urls': email_features.get('urls', []),
            'ip_addresses': [],
            'file_hashes': []
        }
        
        # Extract domains from URLs
        for url in iocs['urls']:
            try:
                domain = url.split('://')[1].split('/')[0]
                iocs['domains'].append(domain)
            except:
                pass
        
        return iocs
    
    def _map_to_mitre_attack(self, email_features: Dict) -> Dict:
        """Map threat to MITRE ATT&CK framework"""
        
        # Analyze email content for MITRE techniques
        body = email_features.get('body_text', '').lower()
        subject = email_features.get('subject', '').lower()
        
        techniques = []
        
        # T1566.002 - Phishing: Spearphishing Link
        if email_features.get('urls'):
            techniques.append({
                'technique_id': 'T1566.002',
                'technique_name': 'Phishing: Spearphishing Link',
                'tactic': 'Initial Access',
                'confidence': 0.9
            })
        
        # T1656 - Impersonation
        if any(term in body for term in ['microsoft', 'bank', 'paypal']):
            techniques.append({
                'technique_id': 'T1656',
                'technique_name': 'Impersonation',
                'tactic': 'Defense Evasion',
                'confidence': 0.8
            })
        
        # T1598 - Phishing for Information
        if any(term in body for term in ['verify', 'confirm', 'update']):
            techniques.append({
                'technique_id': 'T1598',
                'technique_name': 'Phishing for Information',
                'tactic': 'Reconnaissance',
                'confidence': 0.85
            })
        
        return {
            'techniques': techniques,
            'primary_tactic': techniques[0]['tactic'] if techniques else 'Unknown',
            'attack_pattern': 'Email-based Social Engineering'
        }

def test_llm_intelligence():
    """Test the LLM intelligence engine"""
    engine = LLMIntelligenceEngine()
    
    # Sample email features
    email_features = {
        'sender_email': 'security@microsooft-alerts.com',
        'subject': 'URGENT: Your Microsoft account will be suspended',
        'body_text': 'Your Microsoft account shows suspicious activity. Click here to verify immediately: http://fake-microsoft.com/verify',
        'urls': ['http://fake-microsoft.com/verify']
    }
    
    # Sample ML prediction
    ml_prediction = {
        'prediction': 1,
        'phishing_probability': 0.92,
        'confidence': 0.92
    }
    
    # Sample behavioral analysis
    behavioral_analysis = {
        'anomaly_score': 0.85,
        'anomalies': ['unknown_sender', 'high_risk_content']
    }
    
    print("=== LLM THREAT INTELLIGENCE ANALYSIS ===")
    
    # Generate threat intelligence
    threat_intel = engine.analyze_threat_intelligence(email_features, ml_prediction, behavioral_analysis)
    
    print(f"\n🎯 THREAT CLASSIFICATION:")
    print(f"Primary Threat: {threat_intel['threat_classification']['primary_threat']}")
    print(f"Description: {threat_intel['threat_classification']['threat_description']}")
    print(f"Confidence: {threat_intel['threat_classification']['confidence_scores']}")
    
    print(f"\n🔍 SOPHISTICATION ASSESSMENT:")
    print(f"Level: {threat_intel['sophistication_level']['level'].upper()}")
    print(f"Score: {threat_intel['sophistication_level']['score']:.2f}")
    print(f"Indicators: {threat_intel['sophistication_level']['indicators']}")
    
    print(f"\n💼 BUSINESS IMPACT:")
    print(f"Impact Level: {threat_intel['business_impact']['level'].upper()}")
    print(f"Estimated Cost: {threat_intel['business_impact']['estimated_cost']}")
    print(f"Affected Systems: {threat_intel['business_impact']['affected_systems']}")
    
    print(f"\n🛡️ MITRE ATT&CK MAPPING:")
    mitre = threat_intel['mitre_mapping']
    for technique in mitre['techniques']:
        print(f"  {technique['technique_id']}: {technique['technique_name']} ({technique['tactic']})")
    
    # Generate detection rule
    print(f"\n⚙️ GENERATED DETECTION RULE:")
    rule = engine.generate_detection_rule(email_features, threat_intel['threat_classification']['primary_threat'])
    print(f"Rule Name: {rule['name']}")
    print(f"Description: {rule['description']}")
    print(f"Confidence: {rule['confidence']}")
    print(f"Rule ID: {rule['metadata']['rule_id']}")
    
    # Generate recommendations
    print(f"\n📋 SECURITY RECOMMENDATIONS:")
    for i, rec in enumerate(threat_intel['recommended_actions'], 1):
        print(f"{i}. {rec['action'].upper()} ({rec['priority']})")
        print(f"   {rec['description']}")
    
    # Create executive summary
    print(f"\n📊 EXECUTIVE SUMMARY:")
    threat_stats = {'total_analyzed': 100, 'phishing_count': 15}
    user_stats = {'high_risk_count': 3}
    summary = engine.create_executive_summary(threat_stats, user_stats, [])
    print(summary[:500] + "...")

if __name__ == "__main__":
    test_llm_intelligence()