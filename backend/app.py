import pickle
from flask import Flask, request, jsonify
import re
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 
# Load model and vectorizer
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)

sqli_patterns = [
    r"'.+?(--|#|\/\*|\|)",
    r"\b(union|select).+?(from|where).+?\d+=\d+",
    r"\b(drop|alter|truncate)\s+(table|database)",
    r";\s*(declare|exec|shutdown)",
    r"\b(and|or)\s+[\w\d]+\s*=\s*[\w\d]+\s*(--|#)",
    r"'.*?(sleep|benchmark|waitfor|pg_sleep)\(",
    r"\{\s*\"\$where\"\s*:\s*\".+?\b(OR|AND)\b.+?\"\s*\}",
    r"\bEXEC\b.*?\(",
    r"\bLOAD_FILE\s*\(.*?\)",
    r"\bxp_cmdshell\b"
]

def preprocess_query(query):
    query = query.lower()
    if any(ptrn in query for ptrn in ["--", "#", "/*", "*/", "' or ", "' and "]):
        query = re.sub(r"('[^']*')", lambda m: m.group(1).replace(' ', '_'), query)
    else:
        query = re.sub(r"'[^']*'", 'STR', query)
    query = re.sub(r'\b\d+\b', 'NUM', query)
    query = re.sub(r'[^\w\s=/*#\-<>+!@]', ' ', query)
    return ' '.join(query.split())

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    query = data.get('query', '')
    if not query:
        return jsonify({'error': 'No query provided'}), 400

    # Pattern check
    if any(re.search(pattern, query, re.I) for pattern in sqli_patterns):
        is_malicious = 1
        confidence = 1.0
    else:
        clean = preprocess_query(query)
        vec = vectorizer.transform([clean])
        proba = model.predict_proba(vec)[0]
        is_malicious = int(model.predict(vec)[0])
        confidence = float(max(proba))

    return jsonify({
        'is_malicious': bool(is_malicious),
        'confidence': confidence
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)