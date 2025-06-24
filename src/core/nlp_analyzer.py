"""
AI-Driven Phishing Email Detector - NLP Analysis Engine
Advanced text analysis for phishing detection
"""

import re
import spacy
from textblob import TextBlob
from typing import Dict, List, Tuple

class NLPAnalyzer:
    """Advanced NLP analysis for email content"""
    
    def __init__(self):
        # Load spaCy model
        self.nlp = spacy.load("en_core_web_sm")
        
        # Urgency patterns
        self.urgency_patterns = [
            r'\b(urgent|asap|immediate|now|today)\b',
            r'\b(expires?|deadline|final|last)\b',
            r'\b(act now|time sensitive|limited time)\b'
        ]
        
        # Financial keywords
        self.financial_keywords = [
            'account', 'payment', 'bank', 'credit', 'money',
            'refund', 'transfer', 'tax', 'invoice', 'billing'
        ]
        
        # Authority spoofing
        self.authority_terms = [
            'microsoft', 'apple', 'amazon', 'paypal', 'google',
            'bank', 'irs', 'government', 'police', 'security'
        ]
    
    def analyze_text(self, text: str) -> Dict:
        """Main analysis function"""
        if not text:
            return self._empty_analysis()
        
        # Clean text
        clean_text = self._preprocess_text(text)
        
        # Run all analyses
        results = {
            'sentiment': self._analyze_sentiment(clean_text),
            'urgency_score': self._calculate_urgency_score(clean_text),
            'linguistic_features': self._extract_linguistic_features(clean_text),
            'authority_spoofing': self._detect_authority_spoofing(clean_text),
            'financial_context': self._analyze_financial_context(clean_text),
            'readability': self._calculate_readability(clean_text)
        }
        
        return results
    
    def _preprocess_text(self, text: str) -> str:
        """Clean and normalize text"""
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        # Remove HTML tags if present
        text = re.sub(r'<[^>]+>', '', text)
        return text.strip()
    
    def _analyze_sentiment(self, text: str) -> Dict:
        """Analyze emotional tone of the text"""
        blob = TextBlob(text)
        
        return {
            'polarity': blob.sentiment.polarity,  # -1 (negative) to 1 (positive)
            'subjectivity': blob.sentiment.subjectivity,  # 0 (objective) to 1 (subjective)
            'is_negative': blob.sentiment.polarity < -0.1,
            'is_highly_emotional': blob.sentiment.subjectivity > 0.7
        }
    
    def _calculate_urgency_score(self, text: str) -> float:
        """Calculate how urgent the text sounds"""
        text_lower = text.lower()
        urgency_score = 0.0
        
        # Check urgency patterns
        for pattern in self.urgency_patterns:
            matches = len(re.findall(pattern, text_lower))
            urgency_score += matches * 0.2
        
        # Check for excessive punctuation
        exclamation_count = text.count('!')
        if exclamation_count > 2:
            urgency_score += 0.3
        
        # Check for ALL CAPS words
        caps_words = re.findall(r'\b[A-Z]{3,}\b', text)
        if len(caps_words) > 2:
            urgency_score += 0.2
        
        return min(urgency_score, 1.0)
    
    def _extract_linguistic_features(self, text: str) -> Dict:
        """Extract advanced linguistic features using spaCy"""
        doc = self.nlp(text)
        
        # Count different types of words
        nouns = sum(1 for token in doc if token.pos_ == "NOUN")
        verbs = sum(1 for token in doc if token.pos_ == "VERB")
        adjectives = sum(1 for token in doc if token.pos_ == "ADJ")
        
        # Count entities (people, organizations, etc.)
        entities = len(doc.ents)
        person_entities = sum(1 for ent in doc.ents if ent.label_ == "PERSON")
        org_entities = sum(1 for ent in doc.ents if ent.label_ == "ORG")
        
        # Sentence analysis
        sentences = list(doc.sents)
        avg_sentence_length = sum(len(sent) for sent in sentences) / len(sentences) if sentences else 0
        
        return {
            'word_count': len(doc),
            'sentence_count': len(sentences),
            'avg_sentence_length': avg_sentence_length,
            'noun_count': nouns,
            'verb_count': verbs,
            'adjective_count': adjectives,
            'entity_count': entities,
            'person_entities': person_entities,
            'org_entities': org_entities
        }
    
    def _detect_authority_spoofing(self, text: str) -> Dict:
        """Detect attempts to impersonate authority figures"""
        text_lower = text.lower()
        
        found_authorities = []
        for authority in self.authority_terms:
            if authority in text_lower:
                found_authorities.append(authority)
        
        # Check for impersonation phrases
        impersonation_phrases = [
            'we are', 'this is', 'from the', 'on behalf of',
            'authorized by', 'official', 'department'
        ]
        
        impersonation_signals = 0
        for phrase in impersonation_phrases:
            if phrase in text_lower:
                impersonation_signals += 1
        
        return {
            'authority_references': found_authorities,
            'authority_count': len(found_authorities),
            'impersonation_signals': impersonation_signals,
            'likely_spoofing': len(found_authorities) > 0 and impersonation_signals > 1
        }
    
    def _analyze_financial_context(self, text: str) -> Dict:
        """Analyze financial/money-related content"""
        text_lower = text.lower()
        
        financial_terms_found = []
        for term in self.financial_keywords:
            if term in text_lower:
                financial_terms_found.append(term)
        
        # Look for money amounts
        money_pattern = r'[\$£€¥]\s*\d+(?:,\d{3})*(?:\.\d{2})?'
        money_amounts = re.findall(money_pattern, text)
        
        return {
            'financial_terms': financial_terms_found,
            'financial_term_count': len(financial_terms_found),
            'money_amounts': money_amounts,
            'has_financial_context': len(financial_terms_found) > 0 or len(money_amounts) > 0
        }
    
    def _calculate_readability(self, text: str) -> Dict:
        """Calculate how easy the text is to read"""
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        
        if not words or not sentences:
            return {'score': 0, 'level': 'unreadable'}
        
        avg_words_per_sentence = len(words) / len(sentences)
        
        # Simple readability score (higher = harder to read)
        long_words = sum(1 for word in words if len(word) > 6)
        complexity_score = (avg_words_per_sentence * 0.4) + (long_words / len(words) * 100)
        
        # Classify readability
        if complexity_score < 10:
            level = 'very_easy'
        elif complexity_score < 15:
            level = 'easy'
        elif complexity_score < 20:
            level = 'moderate'
        else:
            level = 'difficult'
        
        return {
            'score': complexity_score,
            'level': level,
            'avg_words_per_sentence': avg_words_per_sentence,
            'long_word_percentage': (long_words / len(words)) * 100
        }
    
    def _empty_analysis(self) -> Dict:
        """Return empty analysis for invalid input"""
        return {
            'sentiment': {'polarity': 0, 'subjectivity': 0, 'is_negative': False, 'is_highly_emotional': False},
            'urgency_score': 0.0,
            'linguistic_features': {'word_count': 0, 'sentence_count': 0},
            'authority_spoofing': {'authority_references': [], 'likely_spoofing': False},
            'financial_context': {'financial_terms': [], 'has_financial_context': False},
            'readability': {'score': 0, 'level': 'unreadable'}
        }

# Test function
def test_nlp_analyzer():
    """Test the NLP analyzer"""
    analyzer = NLPAnalyzer()
    
    # Test with phishing email
    phishing_email = """
    URGENT! Your Microsoft account has been SUSPENDED!
    
    We detected suspicious activity on your account. You must verify your identity 
    immediately or your account will be permanently deleted within 24 hours!
    
    Click here NOW to verify: http://fake-microsoft.com
    
    This is an official security alert from Microsoft Security Team.
    Act now before it's too late!
    """
    
    print("=== PHISHING EMAIL ANALYSIS ===")
    results = analyzer.analyze_text(phishing_email)
    
    print(f"Sentiment: {results['sentiment']['polarity']:.2f} (negative: {results['sentiment']['is_negative']})")
    print(f"Urgency Score: {results['urgency_score']:.2f}")
    print(f"Authority References: {results['authority_spoofing']['authority_references']}")
    print(f"Likely Spoofing: {results['authority_spoofing']['likely_spoofing']}")
    print(f"Word Count: {results['linguistic_features']['word_count']}")
    print(f"Readability: {results['readability']['level']}")

if __name__ == "__main__":
    test_nlp_analyzer()