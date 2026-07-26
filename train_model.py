import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODEL_DIR = os.path.join(BASE_DIR, 'trained_model')

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = os.path.join(DATASET_DIR, 'cicids2017_sample.csv')

def generate_synthetic_dataset(num_samples=15000):
    print("Generating simulated network dataset...")
    np.random.seed(42)
    
    columns = [
        'Source_Port', 'Destination_Port', 'Protocol', 'Flow_Duration', 
        'Total_Fwd_Packets', 'Total_Backward_Packets', 'Total_Length_of_Fwd_Packets', 
        'Fwd_Packet_Length_Max', 'Bwd_Packet_Length_Max', 'Flow_Bytes_s', 
        'Flow_Packets_s', 'Label'
    ]
    
    data = []
    labels = ['Normal', 'DoS', 'DDoS', 'Port Scan', 'Bot', 'Brute Force', 'Web Attack']
    weights = [0.60, 0.12, 0.10, 0.08, 0.03, 0.04, 0.03]
    assigned_labels = np.random.choice(labels, size=num_samples, p=weights)
    
    for label in assigned_labels:
        src_port = np.random.randint(1024, 65535)
        dst_port = np.random.choice([80, 443, 8080, 22, 21, 3389, np.random.randint(49152, 65535)])
        proto = np.random.choice([6, 17, 1])
        duration = np.random.exponential(scale=1.5)
        fwd_pkts = np.random.randint(1, 20)
        bwd_pkts = np.random.randint(0, 20)
        fwd_len = float(fwd_pkts * np.random.randint(40, 1000))
        fwd_len_max = float(np.random.randint(40, 1460))
        bwd_len_max = float(np.random.randint(0, 1460)) if bwd_pkts > 0 else 0.0
        
        if label == 'Normal':
            proto = np.random.choice([6, 17], p=[0.7, 0.3])
            duration = np.random.uniform(0.01, 5.0)
            fwd_pkts = np.random.randint(3, 30)
            bwd_pkts = np.random.randint(3, 40)
            fwd_len = float(fwd_pkts * np.random.randint(50, 200))
            fwd_len_max = float(np.random.randint(60, 1000))
            bwd_len_max = float(np.random.randint(60, 1460)) if bwd_pkts > 0 else 0.0
            
        elif label == 'DoS':
            dst_port = np.random.choice([80, 443])
            proto = 6
            duration = np.random.uniform(0.001, 0.2)
            fwd_pkts = np.random.randint(50, 500)
            bwd_pkts = np.random.randint(0, 5)
            fwd_len = float(fwd_pkts * np.random.randint(20, 64))
            fwd_len_max = 64.0
            bwd_len_max = 0.0
            
        elif label == 'DDoS':
            dst_port = np.random.choice([80, 443, 8080])
            proto = 6
            duration = np.random.uniform(0.0001, 0.05)
            fwd_pkts = np.random.randint(100, 1000)
            bwd_pkts = np.random.randint(0, 2)
            fwd_len = float(fwd_pkts * np.random.randint(20, 54))
            fwd_len_max = 54.0
            bwd_len_max = 0.0
            
        elif label == 'Port Scan':
            dst_port = np.random.randint(1, 65535)
            proto = 6
            duration = np.random.uniform(0.0001, 0.01)
            fwd_pkts = np.random.choice([1, 2])
            bwd_pkts = np.random.choice([0, 1])
            fwd_len = float(fwd_pkts * 40)
            fwd_len_max = 40.0
            bwd_len_max = 40.0 if bwd_pkts > 0 else 0.0
            
        elif label == 'Bot':
            dst_port = np.random.choice([8080, 6667, 9050])
            proto = 6
            duration = np.random.uniform(2.0, 10.0)
            fwd_pkts = np.random.randint(5, 15)
            bwd_pkts = np.random.randint(5, 15)
            fwd_len = float(fwd_pkts * np.random.randint(100, 300))
            fwd_len_max = 500.0
            bwd_len_max = 500.0
            
        elif label == 'Brute Force':
            dst_port = np.random.choice([22, 21, 3389])
            proto = 6
            duration = np.random.uniform(0.5, 3.0)
            fwd_pkts = np.random.randint(10, 50)
            bwd_pkts = np.random.randint(10, 50)
            fwd_len = float(fwd_pkts * np.random.randint(40, 100))
            fwd_len_max = 128.0
            bwd_len_max = 128.0
            
        elif label == 'Web Attack':
            dst_port = np.random.choice([80, 443])
            proto = 6
            duration = np.random.uniform(1.0, 8.0)
            fwd_pkts = np.random.randint(15, 80)
            bwd_pkts = np.random.randint(20, 100)
            fwd_len = float(fwd_pkts * np.random.randint(500, 1500))
            fwd_len_max = 1500.0
            bwd_len_max = 1460.0
            
        flow_bytes_s = (fwd_len + (bwd_pkts * bwd_len_max)) / (duration + 1e-6)
        flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration + 1e-6)
        
        row = [
            src_port, dst_port, proto, duration, fwd_pkts, bwd_pkts, 
            fwd_len, fwd_len_max, bwd_len_max, flow_bytes_s, flow_pkts_s, label
        ]
        data.append(row)
        
    df = pd.DataFrame(data, columns=columns)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Dataset saved to {DATASET_PATH}. Rows: {len(df)}")
    return df

def train_model():
    if not os.path.exists(DATASET_PATH):
        df = generate_synthetic_dataset()
    else:
        df = pd.read_csv(DATASET_PATH)
        
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    label_mapping = {int(idx): str(label) for idx, label in enumerate(le.classes_)}
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Training Random Forest Classifier model...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    
    y_pred = rf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True)
    print(f"Training completed. Test Accuracy: {acc * 100:.2f}%")
    
    cm = confusion_matrix(y_test, y_pred)
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    feature_importance = {X.columns[i]: float(importances[i]) for i in indices}
    
    model_file = os.path.join(MODEL_DIR, 'model.joblib')
    scaler_file = os.path.join(MODEL_DIR, 'scaler.joblib')
    joblib.dump(rf, model_file)
    joblib.dump(scaler, scaler_file)
    
    roc_data = {}
    y_test_binarized = pd.get_dummies(y_test).values
    y_score = rf.predict_proba(X_test_scaled)
    
    for idx, class_name in label_mapping.items():
        scores = y_score[:, idx]
        actuals = y_test_binarized[:, idx]
        
        thresholds = np.linspace(0, 1, 11)
        fpr_pts = []
        tpr_pts = []
        for th in thresholds:
            preds = (scores >= th).astype(int)
            tp = np.sum((preds == 1) & (actuals == 1))
            fp = np.sum((preds == 1) & (actuals == 0))
            tn = np.sum((preds == 0) & (actuals == 0))
            fn = np.sum((preds == 0) & (actuals == 1))
            
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fpr_pts.append(float(fpr))
            tpr_pts.append(float(tpr))
            
        roc_data[class_name] = {
            'fpr': fpr_pts[::-1],
            'tpr': tpr_pts[::-1]
        }

    meta = {
        'accuracy': float(acc),
        'precision_avg': float(report['macro avg']['precision']),
        'recall_avg': float(report['macro avg']['recall']),
        'f1_avg': float(report['macro avg']['f1-score']),
        'feature_importance': feature_importance,
        'label_mapping': label_mapping,
        'confusion_matrix': cm.tolist(),
        'roc_curve': roc_data,
        'classes': list(le.classes_),
        'metrics_per_class': {c: report[c] for c in le.classes_}
    }
    
    meta_path = os.path.join(MODEL_DIR, 'model_meta.json')
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=4)
    print(f"Model metadata saved to {meta_path}")

if __name__ == '__main__':
    train_model()
