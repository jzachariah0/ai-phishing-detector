"""
Real Email Dataset Collector
Downloads and processes legitimate and phishing email datasets
"""

import os
import json
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple

class EmailDatasetCollector:
    """Collects and processes real email datasets for ML training"""
    
    def __init__(self):
        self.data_dir = Path("data")
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        
        # Create directories
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
    
    def create_sample_datasets(self) -> Tuple[List[Dict], List[Dict]]:
        """Create sample datasets for training (simulates real data collection)"""
        
        # Sample legitimate emails
        legitimate_emails = [
            {
                'sender': 'hr@company.com',
                'subject': 'Weekly Team Meeting',
                'body': 'Hi team, reminder about our weekly meeting this Thursday at 2 PM. Please bring your project updates.',
                'label': 0  # 0 = legitimate
            },
            {
                'sender': 'newsletter@techcrunch.com',
                'subject': 'Daily Tech News Digest',
                'body': 'Here are today\'s top technology stories. Read about the latest AI developments and startup funding.',
                'label': 0
            },
            {
                'sender': 'support@github.com',
                'subject': 'Your repository has been updated',
                'body': 'Your repository "ai-project" has received 3 new commits. View the changes in your dashboard.',
                'label': 0
            },
            {
                'sender': 'billing@aws.amazon.com',
                'subject': 'Your monthly AWS bill is ready',
                'body': 'Your AWS bill for this month is $23.45. View detailed usage and download your invoice.',
                'label': 0
            },
            {
                'sender': 'noreply@linkedin.com',
                'subject': 'You have 3 new connection requests',
                'body': 'John Smith, Sarah Wilson, and Mike Johnson want to connect with you on LinkedIn.',
                'label': 0
            }
        ]
        
        # Sample phishing emails
        phishing_emails = [
            {
                'sender': 'security@paypaI-alerts.com',  # Note the fake 'I' instead of 'l'
                'subject': 'URGENT: Your PayPal account has been limited',
                'body': 'Your account has been limited due to suspicious activity. Click here immediately to verify your identity and restore access. http://fake-paypal.malicious.com/verify',
                'label': 1  # 1 = phishing
            },
            {
                'sender': 'no-reply@amazon-security.net',
                'subject': 'Your Amazon account will be suspended',
                'body': 'We detected unauthorized access to your account. Verify your identity now or your account will be permanently suspended. Act fast! http://amazon-fake.evil.com',
                'label': 1
            },
            {
                'sender': 'alerts@microsoft-team.org',
                'subject': 'Microsoft Security Alert - Action Required',
                'body': 'Your Microsoft account shows signs of compromise. Download our security tool immediately to protect your data. http://microsoft-security-fake.com/download',
                'label': 1
            },
            {
                'sender': 'service@chase-bankaccount.info',
                'subject': 'Your account has been frozen - Immediate action required',
                'body': 'Your Chase bank account has been frozen due to suspicious transactions. Log in immediately to unlock: http://chase-unlock.suspicious.com',
                'label': 1
            },
            {
                'sender': 'irs-refund@government-official.org',
                'subject': 'You are eligible for a $2,847 tax refund',
                'body': 'The IRS has processed your tax return. You are eligible for a refund of $2,847. Claim now before it expires: http://irs-refund-claim.fake.gov',
                'label': 1
            }
        ]
        
        return legitimate_emails, phishing_emails
    
    def process_and_save_datasets(self):
        """Process datasets and save for ML training"""
        print("Creating sample email datasets...")
        
        legitimate_emails, phishing_emails = self.create_sample_datasets()
        
        # Combine all emails
        all_emails = legitimate_emails + phishing_emails
        
        # Convert to DataFrame
        df = pd.DataFrame(all_emails)
        
        # Save to CSV
        csv_path = self.processed_dir / "email_dataset.csv"
        df.to_csv(csv_path, index=False)
        
        print(f"Dataset saved to: {csv_path}")
        print(f"Total emails: {len(all_emails)}")
        print(f"Legitimate emails: {len(legitimate_emails)}")
        print(f"Phishing emails: {len(phishing_emails)}")
        
        # Save metadata
        metadata = {
            'total_emails': len(all_emails),
            'legitimate_count': len(legitimate_emails),
            'phishing_count': len(phishing_emails),
            'features': ['sender', 'subject', 'body', 'label'],
            'label_encoding': {'0': 'legitimate', '1': 'phishing'}
        }
        
        metadata_path = self.processed_dir / "dataset_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Metadata saved to: {metadata_path}")
        return csv_path

def test_data_collector():
    """Test the data collector"""
    collector = EmailDatasetCollector()
    dataset_path = collector.process_and_save_datasets()
    
    # Load and display sample
    df = pd.read_csv(dataset_path)
    print("\n=== DATASET SAMPLE ===")
    print(df.head())
    print(f"\nDataset shape: {df.shape}")
    print(f"Label distribution:\n{df['label'].value_counts()}")

if __name__ == "__main__":
    test_data_collector()