import os
import pickle
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Create models directory if it doesn't exist
os.makedirs('models', exist_ok=True)

# 1. SQL Injection Model
def train_sql_model():
    # Synthetic SQL injection data
    sql_data = [
        "SELECT * FROM users WHERE id = 1",
        "1; DROP TABLE users; --",
        "SELECT * FROM products WHERE name = 'test'",
        "' OR '1'='1",
        "admin' --",
        "SELECT * FROM orders WHERE date = '2023-01-01'",
        "UNION SELECT password FROM users",
        "SELECT * FROM items WHERE price < 100",
        "' OR ''='",
        "EXEC xp_cmdshell 'net user'"
    ]
    labels = [0, 1, 0, 1, 1, 0, 1, 0, 1, 1]  # 0: safe, 1: malicious

    # Vectorize queries
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3))
    X = vectorizer.fit_transform(sql_data)
    y = np.array(labels)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    # Save model and vectorizer
    with open('models/sql_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open('models/vectorizer.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)
    print("SQL model and vectorizer trained and saved.")

# 2. Malware Detection Model
def train_malware_model():
    # Synthetic malware features: [filename_length, file_size_kb, has_suspicious_keyword]
    data = []
    labels = []
    for _ in range(1000):
        fname_len = np.random.randint(5, 50)
        file_size = np.random.uniform(10, 10000)
        keywords = ['malware', 'virus', 'trojan', 'ransom']
        has_keyword = np.random.choice([0, 1], p=[0.7, 0.3])
        data.append([fname_len, file_size, has_keyword])
        # Label as malicious if file_size is large or has suspicious keyword
        is_malware = 1 if (file_size > 5000 or has_keyword) else 0
        labels.append(is_malware)

    X = np.array(data)
    y = np.array(labels)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)
    print(f"Malware model accuracy: {model.score(X_test, y_test):.2f}")

    # Save model
    with open('models/malware_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("Malware model trained and saved.")

# 3. Brute Force Detection Model
def train_brute_model():
    # Synthetic brute force features: [attempt_count, time_window_seconds]
    data = []
    labels = []
    for _ in range(1000):
        attempts = np.random.randint(1, 20)
        time_window = np.random.uniform(1, 120)
        data.append([attempts, time_window])
        # Label as brute force if many attempts in short time
        is_brute = 1 if attempts > 5 and time_window < 60 else 0
        labels.append(is_brute)

    X = np.array(data)
    y = np.array(labels)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)
    print(f"Brute force model accuracy: {model.score(X_test, y_test):.2f}")

    # Save model
    with open('models/brute_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("Brute force model trained and saved.")

# 4. DDoS Detection Model
def train_ddos_model():
    # Synthetic DDoS features: [request_count, time_window_seconds]
    data = []
    labels = []
    for _ in range(1000):
        requests = np.random.randint(1, 50)
        time_window = np.random.uniform(1, 120)
        data.append([requests, time_window])
        # Label as DDoS if many requests in short time
        is_ddos = 1 if requests > 10 and time_window < 30 else 0
        labels.append(is_ddos)

    X = np.array(data)
    y = np.array(labels)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)
    print(f"DDoS model accuracy: {model.score(X_test, y_test):.2f}")

    # Save model
    with open('models/ddos_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("DDoS model trained and saved.")

if __name__ == "__main__":
    print("Starting model training...")
    train_sql_model()
    train_malware_model()
    train_brute_model()
    train_ddos_model()
    print("All models trained and saved successfully.")