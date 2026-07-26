# AI-Integrated Web-Based Network Intrusion Detection System (AI-NIDS)

A full-stack SOC dashboard that integrates real-time packet capturing (via Scapy or custom fallback simulator), heuristic rules, and a Random Forest Classifier trained on CICIDS2017 features.

## Setup & Installation

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
*Note: Raw socket sniffing via Scapy on Windows requires Npcap. If not installed, the application falls back to simulation mode.*

### 2. Train the Random Forest Model
This script generates simulated network traffic dataset (15,000 samples) and trains the classifier:
```bash
python train_model.py
```

### 3. Run unit tests
```bash
python test_app.py
```

### 4. Run the web server
```bash
python run.py
```
Open your browser and navigate to: http://127.0.0.1:5000

## Default Credentials
The database is auto-provisioned with the following login details:

- **Admin Account**: `admin` / `password123`
- **Analyst Account**: `analyst` / `password123`
