import pickle
from flask import Flask, render_template, request
import re

app = Flask(__name__)

# Load the trained model
model = pickle.load(open('model.pkl', 'rb'))

# Feature extraction logic
def extract_features(url):
    features = []
    features.append(len(url))  # Length of the URL
    features.append(url.count('.'))  # Number of dots
    features.append(url.count('-'))  # Number of hyphens
    features.append(url.count('@'))  # Number of '@' symbols
    features.append(sum(c.isdigit() for c in url))  # Number of digits
    features.append(1 if url.lower().startswith('https') else 0)  # HTTPS check
    features.append(1 if re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', url) else 0)  # Contains IP
    suspicious_words = ['free', 'login', 'update', 'secure', 'account', 'verify', 'bank', 'confirm', 'password']
    features.append(int(any(word in url.lower() for word in suspicious_words)))  # Suspicious keywords
    return features

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Prediction route
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url', '').strip()

    if not url:
        return render_template('result.html', prediction="❌ No URL entered!", url="N/A")

    features = extract_features(url)
    prediction = model.predict([features])[0]

    # Clean result label
    result_label = "Safe" if prediction == 0 else "Phishing"

    return render_template('result.html', prediction=result_label, url=url)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
