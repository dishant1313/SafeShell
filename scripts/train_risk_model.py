"""SafeShell Phase 3 - XGBoost Risk Model Trainer.

Trains the fuzzy risk classifier on the synthetic corpus, dropping critical rows
since they are handled deterministically by the rules engine.
"""

import os
import csv
import json
import joblib
from datetime import datetime
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from safeshell.classifier import FAMILY_TABLE

def main():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    corpus_path = os.path.join(base_dir, 'data', 'synthetic_risk_corpus.csv')
    
    if not os.path.exists(corpus_path):
        print("Corpus not found. Run data/gen_risk_corpus.py first.")
        return
        
    X_list = []
    y_list = []
    
    label_map = {'low': 0, 'medium': 1, 'high': 2}
    
    with open(corpus_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['labeled_critical'] == 'True':
                continue
                
            features = [
                float(row['recursive']), float(row['force']), float(row['wildcards']),
                float(row['pipe_to_shell']), float(row['redirect_write']), float(row['priv_esc']),
                float(row['path_etc']), float(row['path_boot']), float(row['path_dev']),
                float(row['path_var']), float(row['path_usr']), float(row['directory_target']),
                float(row['compound_ops']), float(row['unknown_effects']), float(row['deletes_count']),
                float(row['creates_count']), float(row['modifies_count']), float(row['permissions_count']),
                float(row['service_count']), float(row['network_count']), float(row['target_file_count']),
                float(row['exec_family_id'])
            ]
            X_list.append(features)
            y_list.append(label_map[row['label']])
            
    X_train, X_test, y_train, y_test = train_test_split(
        X_list, y_list, test_size=0.2, random_state=42, stratify=y_list
    )
    
    model = XGBClassifier(
        max_depth=4,
        n_estimators=120,
        objective="multi:softprob",
        num_class=3,
        seed=42,
        eval_metric='mlogloss'
    )
    
    print("Training XGBoost model...")
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['low', 'medium', 'high']))
    
    assert acc >= 0.90, f"Accuracy {acc} is below required 0.90 threshold"
    
    model_dir = os.path.join(base_dir, 'models')
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, 'risk_model.joblib')
    joblib.dump(model, model_path)
    
    feature_cols = [
        'recursive', 'force', 'wildcards', 'pipe_to_shell', 'redirect_write', 'priv_esc',
        'path_etc', 'path_boot', 'path_dev', 'path_var', 'path_usr', 'directory_target',
        'compound_ops', 'unknown_effects', 'deletes_count', 'creates_count', 'modifies_count',
        'permissions_count', 'service_count', 'network_count', 'target_file_count', 'exec_family_id'
    ]
    
    meta_path = os.path.join(model_dir, 'risk_model_meta.json')
    meta = {
        'feature_order': feature_cols,
        'family_table': FAMILY_TABLE,
        'thresholds': [0.35, 0.65],
        'trained_at': datetime.utcnow().isoformat(),
        'accuracy': acc
    }
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
        
    print(f"Model saved to {model_path}")
    print(f"Metadata saved to {meta_path}")

if __name__ == "__main__":
    main()
