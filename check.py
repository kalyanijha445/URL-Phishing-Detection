import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle
import re
import numpy as np

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_digits'] = sum(c.isdigit() for c in url)
    features['has_https'] = 1 if url.lower().startswith('https') else 0
    features['has_ip'] = 1 if re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', url) else 0
    suspicious_words = ['free', 'login', 'update', 'secure', 'account', 'verify', 'bank', 'confirm', 'password']
    features['suspicious_words'] = int(any(word in url.lower() for word in suspicious_words))
    return list(features.values())

# Load data
data = pd.read_csv('phishing_url.csv')

# Extract features for all URLs
X = np.array(data['url'].apply(extract_features).tolist())
y = data['label']

# Train model
model = RandomForestClassifier(random_state=42)
model.fit(X, y)

# Save model
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
