"""
AI-Driven Phishing Email Detector - Web Application
Professional Flask interface for live demos and production use
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
import secrets
import sys
from pathlib import Path

# Simplified imports for Heroku deployment
try:
    from src.core.integrated_detector import IntegratedPhishingDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("ML components not available - running in demo mode")

# Modify init_detector function
def init_detector():
    global detector, behavior_analyzer
    try:
        if ML_AVAILABLE:
            detector = IntegratedPhishingDetector()
            behavior_analyzer = UserBehaviorAnalyzer()
        else:
            detector = None
            behavior_analyzer = None
        print("✅ System initialized!")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        detector = None
        behavior_analyzer = None
        return False
    
    

# Add src to path so we can import our modules
sys.path.append(str(Path(__file__).parent / 'src' / 'core'))

try:
    from integrated_detector import IntegratedPhishingDetector
    from user_behavior import UserBehaviorAnalyzer
except ImportError as e:
    print(f"Import error: {e}")
    print("Please make sure all core modules are in src/core/")

app = Flask(__name__, template_folder='frontend/templates')
app.secret_key = secrets.token_hex(16)
CORS(app)

# Global detector instance
detector = None
behavior_analyzer = None

def init_detector():
    """Initialize the detection system"""
    global detector, behavior_analyzer
    try:
        print("Initializing AI Detection System...")
        detector = IntegratedPhishingDetector()
        behavior_analyzer = UserBehaviorAnalyzer()
        print("✅ AI System Ready!")
        return True
    except Exception as e:
        print(f"❌ Error initializing detector: {e}")
        return False

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Email analysis page"""
    if request.method == 'GET':
        return render_template('analyze.html')
    
    try:
        # Get form data
        email_content = request.form.get('email_content', '')
        user_email = request.form.get('user_email', 'demo@company.com')
        
        if not email_content.strip():
            return jsonify({'error': 'Please provide email content to analyze'}), 400
        
        # Get or create user
        if not session.get('user_id'):
            user_id = behavior_analyzer.create_user(
                username=user_email.split('@')[0],
                email=user_email
            )
            session['user_id'] = user_id
            session['user_email'] = user_email
        else:
            user_id = session['user_id']
        
        # Run analysis
        print(f"Analyzing email for user: {user_id}")
        analysis_results = detector.analyze_email(user_id, email_content)
        
        # Format results for web display
        web_results = format_analysis_for_web(analysis_results)
        
        return jsonify({
            'success': True,
            'results': web_results,
            'user_id': user_id
        })
        
    except Exception as e:
        print(f"Analysis error: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/user-stats')
def user_stats():
    """Get user statistics"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'No user session found'}), 400
        
        stats = behavior_analyzer.get_user_stats(user_id)
        return jsonify({'success': True, 'stats': stats})
        
    except Exception as e:
        return jsonify({'error': f'Failed to get user stats: {str(e)}'}), 500

@app.route('/demo-samples')
def demo_samples():
    """Provide demo email samples"""
    samples = {
        'phishing': {
            'name': 'Microsoft Phishing Attack',
            'content': '''From: security-alerts@microsooft-team.com
Subject: URGENT: Your Microsoft account will be suspended
To: user@company.com

Dear Microsoft User,

We detected suspicious activity on your account. Your account will be SUSPENDED in 24 hours unless you verify your identity immediately.

CLICK HERE TO VERIFY NOW: http://fake-microsoft-verify.suspicious.com/urgent

This is your FINAL WARNING. Act now to prevent account deletion.

Microsoft Security Team'''
        },
        'legitimate': {
            'name': 'Legitimate Company Email',
            'content': '''From: hr@company.com
Subject: Team Meeting Tomorrow - Q4 Planning
To: user@company.com

Hi Team,

Just a reminder about our quarterly planning meeting tomorrow at 2 PM in Conference Room A.

Please bring:
- Q3 performance reports
- Q4 project proposals
- Budget planning documents

Looking forward to seeing everyone there!

Best regards,
Sarah Johnson
HR Manager'''
        },
        'sophisticated': {
            'name': 'Sophisticated Banking Phish',
            'content': '''From: alerts@chase-security-center.net
Subject: Security Alert: Unusual Account Activity Detected
To: user@company.com

Dear Valued Customer,

Our fraud detection system has identified potentially unauthorized transactions on your Chase account ending in 4829.

Recent Activity:
- Dec 23: ATM withdrawal $500 - Location: Unknown
- Dec 23: Online purchase $299.99 - Merchant: Unknown

For your security, we have temporarily limited your account access. To restore full access and review these transactions, please verify your identity through our secure portal.

Verify Account: https://chase-secure-verification.account-services.net/verify

If you did not authorize these transactions, please contact us immediately at 1-800-CHASE-1.

Thank you for banking with Chase.

Chase Security Department
Member FDIC'''
        }
    }
    
    return jsonify({'success': True, 'samples': samples})

@app.route('/system-status')
def system_status():
    """Get system status and statistics"""
    try:
        # Mock system statistics for demo
        status = {
            'system_online': detector is not None,
            'analysis_count_today': 127,
            'threats_blocked_today': 23,
            'accuracy_rate': 94.2,
            'avg_analysis_time': 0.12,
            'active_users': 5,
            'rules_generated': 45,
            'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify({'success': True, 'status': status})
        
    except Exception as e:
        return jsonify({'error': f'Failed to get system status: {str(e)}'}), 500

def format_analysis_for_web(analysis_results):
    """Format analysis results for web display"""
    
    risk_assessment = analysis_results['risk_assessment']
    threat_intel = analysis_results['email_analysis']['threat_intelligence']
    email_basic = analysis_results['email_analysis']['basic_features']
    
    # Risk level color coding
    risk_colors = {
        'CRITICAL': '#dc3545',  # Red
        'HIGH': '#fd7e14',      # Orange
        'MEDIUM': '#ffc107',    # Yellow
        'LOW': '#28a745',       # Green
        'MINIMAL': '#6c757d'    # Gray
    }
    
    formatted = {
        'analysis_id': analysis_results['analysis_metadata']['analysis_id'],
        'timestamp': analysis_results['analysis_metadata']['timestamp'],
        'duration': analysis_results['analysis_metadata']['duration_seconds'],
        
        'risk_assessment': {
            'final_score': round(risk_assessment['final_score'], 3),
            'risk_level': risk_assessment['risk_level'],
            'risk_color': risk_colors.get(risk_assessment['risk_level'], '#6c757d'),
            'recommended_action': risk_assessment['recommended_action'],
            'is_phishing': risk_assessment['is_phishing'],
            'confidence': round(risk_assessment['confidence'], 3),
            'reasoning': risk_assessment['reasoning']
        },
        
        'email_summary': {
            'sender': email_basic['sender'],
            'subject': email_basic['subject'],
            'body_length': email_basic['body_length'],
            'url_count': email_basic['url_count'],
            'suspicious_keywords': email_basic['suspicious_keyword_count']
        },
        
        'component_scores': {
            name: round(score, 3) for name, score in risk_assessment['component_scores'].items()
        },
        
        'threat_intelligence': {
            'primary_threat': threat_intel['threat_classification']['primary_threat'].replace('_', ' ').title(),
            'sophistication': threat_intel['sophistication_level']['level'].title(),
            'business_impact': threat_intel['business_impact']['level'].title(),
            'mitre_techniques': [
                {
                    'id': t['technique_id'],
                    'name': t['technique_name'],
                    'tactic': t['tactic']
                } for t in threat_intel['mitre_mapping']['techniques'][:3]
            ]
        },
        
        'recommendations': [
            {
                'priority': rec['priority'],
                'action': rec['action'],
                'description': rec['description'],
                'timeline': rec['timeline']
            } for rec in analysis_results['security_recommendations'][:5]
        ],
        
        'generated_rules': [
            {
                'name': rule['name'],
                'description': rule['description'],
                'confidence': rule['confidence'],
                'rule_type': rule.get('rule_type', 'unknown')
            } for rule in analysis_results['generated_rules']
        ],
        
        'executive_summary': analysis_results['executive_summary']
    }
    
    return formatted

# Initialize the detector when the app starts
with app.app_context():
    def startup():
        """Initialize the AI system on startup"""
        if not init_detector():
            print("⚠️  Warning: AI system not initialized. Some features may not work.")
    startup()

if __name__ == '__main__':
    # Initialize detector
    init_detector()
    
    print("\n" + "="*60)
    print("🚀 AI-DRIVEN PHISHING DETECTOR - WEB APPLICATION")
    print("="*60)
    print("🌐 Starting web server...")
    print("🔒 AI Detection System: Ready")
    print("📊 Real-time Analytics: Enabled")
    print("="*60)
    
    # Run the Flask app
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)