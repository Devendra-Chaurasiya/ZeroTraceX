
import unittest
import shutil
import os
import random
from predict import FlowPredictor

class TestZeroDayML(unittest.TestCase):
    def setUp(self):
        # clean up previous models/buffers
        if os.path.exists("ml/models/live/system_baseline.csv"):
            os.remove("ml/models/live/system_baseline.csv")
        if os.path.exists("ml/models/live/system_iforest.pkl"):
            os.remove("ml/models/live/system_iforest.pkl")
            
        self.predictor = FlowPredictor()

    def test_system_learning_cycle(self):
        print("\n[Test] Starting Learning Cycle...")
        
        # 1. Feed Normal Data (Learning)
        # Simulate normal usage: CPU 5-20%, RAM 40-50%, Net Low
        print("[Test] Feeding 105 normal samples...")
        for _ in range(105):
            sample = {
                "cpu": random.uniform(5.0, 20.0),
                "memory": random.uniform(40.0, 50.0),
                "proc_count": 150,
                "net_sent": random.uniform(100, 5000),
                "net_recv": random.uniform(100, 5000)
            }
            res = self.predictor.predict_system_anomaly(sample)
            
        # 2. Check if model trained (File should exist)
        self.assertTrue(os.path.exists(self.predictor.SYSTEM_MODEL_FILE), "System model should be created after 100 samples")
        
        # Reload predictor to pick up the new model
        print("[Test] Reloading Predictor to load new model...")
        self.predictor = FlowPredictor()
        self.assertTrue(self.predictor.system_model_loaded, "System model should be loaded")

        # 3. Test Anomaly
        print("[Test] Testing Zero-Day Anomaly (Crypto Miner pattern)...")
        anomaly_sample = {
            "cpu": 95.0,          # SPIKE
            "memory": 80.0,       # HIGH
            "proc_count": 155,
            "net_sent": 5000000,  # MASSIVE DATA EXFIL
            "net_recv": 100
        }
        res = self.predictor.predict_system_anomaly(anomaly_sample)
        print(f"[Result] Anomaly Score: {res['score']}, Classification: {res['anomaly']}")
        
        self.assertTrue(res['anomaly'], "Should detect high CPU/Net usage as anomaly")
        
        # 4. Test Normal again
        normal_sample = {
            "cpu": 10.0,
            "memory": 45.0,
            "proc_count": 150,
            "net_sent": 2000,
            "net_recv": 2000
        }
        res = self.predictor.predict_system_anomaly(normal_sample)
        self.assertFalse(res['anomaly'], "Should correctly classify normal traffic")

if __name__ == '__main__':
    unittest.main()
