"""
Real User Behavioral Analysis System
Builds dynamic user profiles and detects anomalies
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import hashlib
import statistics

class UserBehaviorAnalyzer:
    """Analyzes user email behavior patterns and detects anomalies"""
    
    def __init__(self, db_path: str = "data/user_behavior.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize the user behavior database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Email interactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                email_hash TEXT,
                sender TEXT,
                subject TEXT,
                interaction_type TEXT,  -- 'received', 'opened', 'clicked', 'reported'
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_score REAL,
                was_phishing BOOLEAN,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # User behavior profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id TEXT PRIMARY KEY,
                avg_emails_per_day REAL,
                common_senders TEXT,  -- JSON list
                typical_subjects TEXT,  -- JSON list
                active_hours TEXT,  -- JSON list of hours
                click_rate REAL,
                report_rate REAL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("User behavior database initialized")
    
    def create_user(self, username: str, email: str) -> str:
        """Create a new user and return user_id"""
        user_id = hashlib.sha256(f"{username}{email}".encode()).hexdigest()[:12]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (user_id, username, email)
                VALUES (?, ?, ?)
            ''', (user_id, username, email))
            
            # Initialize empty profile
            cursor.execute('''
                INSERT INTO user_profiles (user_id, avg_emails_per_day, common_senders, 
                                         typical_subjects, active_hours, click_rate, report_rate)
                VALUES (?, 0, '[]', '[]', '[]', 0.0, 0.0)
            ''', (user_id,))
            
            conn.commit()
            print(f"User created: {username} (ID: {user_id})")
            return user_id
            
        except sqlite3.IntegrityError:
            print(f"User already exists: {username}")
            cursor.execute('SELECT user_id FROM users WHERE username = ?', (username,))
            return cursor.fetchone()[0]
        finally:
            conn.close()
    
    def log_email_interaction(self, user_id: str, sender: str, subject: str, 
                            interaction_type: str, risk_score: float = 0.0, 
                            was_phishing: bool = False):
        """Log user interaction with an email"""
        email_content = f"{sender}{subject}"
        email_hash = hashlib.sha256(email_content.encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO email_interactions 
            (user_id, email_hash, sender, subject, interaction_type, risk_score, was_phishing)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, email_hash, sender, subject, interaction_type, risk_score, was_phishing))
        
        conn.commit()
        conn.close()
        
        # Update user profile after logging interaction
        self.update_user_profile(user_id)
    
    def update_user_profile(self, user_id: str):
        """Update user's behavioral profile based on recent activity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get last 30 days of interactions
        thirty_days_ago = datetime.now() - timedelta(days=30)
        
        cursor.execute('''
            SELECT sender, subject, interaction_type, timestamp, risk_score, was_phishing
            FROM email_interactions 
            WHERE user_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (user_id, thirty_days_ago))
        
        interactions = cursor.fetchall()
        
        if not interactions:
            conn.close()
            return
        
        # Calculate behavioral metrics
        total_emails = len([i for i in interactions if i[2] == 'received'])
        avg_emails_per_day = total_emails / 30.0
        
        # Common senders (top 10)
        senders = [i[0] for i in interactions if i[2] == 'received']
        sender_counts = {}
        for sender in senders:
            sender_counts[sender] = sender_counts.get(sender, 0) + 1
        common_senders = sorted(sender_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        common_senders = [sender for sender, count in common_senders]
        
        # Typical subject patterns (extract keywords)
        subjects = [i[1] for i in interactions if i[2] == 'received']
        subject_keywords = []
        for subject in subjects:
            words = subject.lower().split()
            subject_keywords.extend([w for w in words if len(w) > 3])
        
        keyword_counts = {}
        for keyword in subject_keywords:
            keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
        typical_subjects = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        typical_subjects = [keyword for keyword, count in typical_subjects]
        
        # Active hours analysis
        timestamps = [datetime.fromisoformat(i[3]) for i in interactions]
        active_hours = [t.hour for t in timestamps]
        hour_counts = {}
        for hour in active_hours:
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        # Get most active hours
        active_hours_sorted = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
        most_active_hours = [hour for hour, count in active_hours_sorted[:8]]
        
        # Calculate click and report rates
        clicked_emails = len([i for i in interactions if i[2] == 'clicked'])
        reported_emails = len([i for i in interactions if i[2] == 'reported'])
        
        click_rate = clicked_emails / total_emails if total_emails > 0 else 0.0
        report_rate = reported_emails / total_emails if total_emails > 0 else 0.0
        
        # Update profile
        cursor.execute('''
            UPDATE user_profiles 
            SET avg_emails_per_day = ?, common_senders = ?, typical_subjects = ?,
                active_hours = ?, click_rate = ?, report_rate = ?, last_updated = ?
            WHERE user_id = ?
        ''', (avg_emails_per_day, json.dumps(common_senders), json.dumps(typical_subjects),
              json.dumps(most_active_hours), click_rate, report_rate, datetime.now(), user_id))
        
        conn.commit()
        conn.close()
        
        print(f"Updated profile for user {user_id}")
    
    def detect_anomalies(self, user_id: str, sender: str, subject: str, 
                        current_hour: int, risk_score: float) -> Dict:
        """Detect behavioral anomalies for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get user profile
        cursor.execute('''
            SELECT avg_emails_per_day, common_senders, typical_subjects, 
                   active_hours, click_rate, report_rate
            FROM user_profiles WHERE user_id = ?
        ''', (user_id,))
        
        profile = cursor.fetchone()
        conn.close()
        
        if not profile:
            return {'anomaly_score': 0.0, 'anomalies': [], 'baseline_established': False}
        
        anomalies = []
        anomaly_score = 0.0
        
        # Parse JSON fields
        common_senders = json.loads(profile[1])
        typical_subjects = json.loads(profile[2])
        active_hours = json.loads(profile[3])
        
        # Check sender anomaly
        if sender not in common_senders and len(common_senders) > 0:
            anomalies.append('unknown_sender')
            anomaly_score += 0.3
        
        # Check subject anomaly
        subject_words = subject.lower().split()
        subject_match = any(keyword in subject_words for keyword in typical_subjects)
        if not subject_match and len(typical_subjects) > 0:
            anomalies.append('unusual_subject')
            anomaly_score += 0.2
        
        # Check time anomaly
        if current_hour not in active_hours and len(active_hours) > 0:
            anomalies.append('unusual_time')
            anomaly_score += 0.2
        
        # Check if risk score is much higher than usual
        if risk_score > 0.7:  # High risk email
            anomalies.append('high_risk_content')
            anomaly_score += 0.4
        
        # Get recent activity pattern
        recent_activity = self.get_recent_activity_anomalies(user_id)
        if recent_activity['unusual_volume']:
            anomalies.append('unusual_email_volume')
            anomaly_score += 0.3
        
        return {
            'anomaly_score': min(anomaly_score, 1.0),
            'anomalies': anomalies,
            'baseline_established': len(common_senders) > 0,
            'user_profile_summary': {
                'avg_emails_per_day': profile[0],
                'known_senders': len(common_senders),
                'typical_keywords': len(typical_subjects),
                'active_hours': active_hours,
                'click_rate': profile[4],
                'report_rate': profile[5]
            }
        }
    
    def get_recent_activity_anomalies(self, user_id: str) -> Dict:
        """Check for recent activity anomalies"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get today's email count
        today = datetime.now().date()
        cursor.execute('''
            SELECT COUNT(*) FROM email_interactions 
            WHERE user_id = ? AND DATE(timestamp) = ? AND interaction_type = 'received'
        ''', (user_id, today))
        
        today_count = cursor.fetchone()[0]
        
        # Get average from profile
        cursor.execute('SELECT avg_emails_per_day FROM user_profiles WHERE user_id = ?', (user_id,))
        avg_result = cursor.fetchone()
        avg_emails = avg_result[0] if avg_result else 0
        
        conn.close()
        
        # Check if today's volume is unusual
        unusual_volume = False
        if avg_emails > 0:
            if today_count > avg_emails * 2:  # More than double average
                unusual_volume = True
            elif today_count == 0 and avg_emails > 2:  # No emails when usually active
                unusual_volume = True
        
        return {
            'unusual_volume': unusual_volume,
            'today_count': today_count,
            'average_count': avg_emails
        }
    
    def get_user_stats(self, user_id: str) -> Dict:
        """Get comprehensive user statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get user info
        cursor.execute('SELECT username, email FROM users WHERE user_id = ?', (user_id,))
        user_info = cursor.fetchone()
        
        # Get profile
        cursor.execute('''
            SELECT avg_emails_per_day, common_senders, click_rate, report_rate
            FROM user_profiles WHERE user_id = ?
        ''', (user_id,))
        profile = cursor.fetchone()
        
        # Get total interactions
        cursor.execute('SELECT COUNT(*) FROM email_interactions WHERE user_id = ?', (user_id,))
        total_interactions = cursor.fetchone()[0]
        
        # Get phishing encounters
        cursor.execute('''
            SELECT COUNT(*) FROM email_interactions 
            WHERE user_id = ? AND was_phishing = 1
        ''', (user_id,))
        phishing_encounters = cursor.fetchone()[0]
        
        conn.close()
        
        if not user_info or not profile:
            return {}
        
        return {
            'username': user_info[0],
            'email': user_info[1],
            'total_interactions': total_interactions,
            'avg_emails_per_day': profile[0],
            'click_rate': profile[1],
            'report_rate': profile[2],
            'phishing_encounters': phishing_encounters,
            'security_awareness': 'High' if profile[3] > 0.1 else 'Medium' if profile[2] < 0.3 else 'Low'
        }

def test_user_behavior():
    """Test the user behavior analysis system"""
    analyzer = UserBehaviorAnalyzer()
    
    # Create test users
    print("=== CREATING TEST USERS ===")
    user1_id = analyzer.create_user("john_doe", "john@company.com")
    user2_id = analyzer.create_user("jane_smith", "jane@company.com")
    
    # Simulate normal email activity for user1
    print(f"\n=== BUILDING BASELINE FOR USER 1 ({user1_id}) ===")
    normal_emails = [
        ("hr@company.com", "Weekly team meeting", "received"),
        ("newsletter@techcrunch.com", "Daily tech news", "received"),
        ("github@notifications.com", "Pull request update", "received"),
        ("hr@company.com", "Company announcement", "received"),
        ("billing@aws.amazon.com", "Monthly bill", "received"),
    ]
    
    for sender, subject, interaction in normal_emails:
        analyzer.log_email_interaction(user1_id, sender, subject, interaction, 0.1)
    
    # Test anomaly detection
    print(f"\n=== TESTING ANOMALY DETECTION ===")
    
    # Test normal email (should have low anomaly score)
    normal_anomaly = analyzer.detect_anomalies(
        user1_id, "hr@company.com", "Team meeting update", 14, 0.1
    )
    
    print(f"🟢 NORMAL EMAIL ANOMALY CHECK:")
    print(f"   Anomaly Score: {normal_anomaly['anomaly_score']:.2f}")
    print(f"   Anomalies: {normal_anomaly['anomalies']}")
    
    # Test suspicious email (should have high anomaly score)
    suspicious_anomaly = analyzer.detect_anomalies(
        user1_id, "security@suspicious-bank.com", "URGENT account verification", 3, 0.9
    )
    
    print(f"\n🔴 SUSPICIOUS EMAIL ANOMALY CHECK:")
    print(f"   Anomaly Score: {suspicious_anomaly['anomaly_score']:.2f}")
    print(f"   Anomalies: {suspicious_anomaly['anomalies']}")
    
    # Get user stats
    print(f"\n=== USER STATISTICS ===")
    stats = analyzer.get_user_stats(user1_id)
    print(f"Username: {stats['username']}")
    print(f"Total Interactions: {stats['total_interactions']}")
    print(f"Avg Emails/Day: {stats['avg_emails_per_day']:.1f}")
    print(f"Security Awareness: {stats['security_awareness']}")

if __name__ == "__main__":
    test_user_behavior()