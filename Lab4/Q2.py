import random
import logging
import json
import os
from Crypto.Util import number
from datetime import datetime, timedelta, timezone

# Setup logging
logging.basicConfig(level=logging.INFO, filename='rabin_kms.log', filemode='a')

class RabinKeyManager:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}
        self.expiry_time = timedelta(days=365)  # 12 months
        self.storage_file = "rabin_keys_secure.json"
        self.load_keys()

    def generate_prime(self):
        while True:
            p = number.getPrime(self.key_size // 2)
            if p % 4 == 3:
                return p

    def generate_keys(self, entity_id):
        p = self.generate_prime()
        q = self.generate_prime()
        n = p * q
        self.keys[entity_id] = {
            "public_key": n,
            "private_key": {"p": p, "q": q},
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        self.save_keys()
        logging.info(f"[{datetime.now(timezone.utc)}] Generated keys for {entity_id}")

    def get_public_key(self, entity_id):
        return self.keys[entity_id]["public_key"]

    def revoke_key(self, entity_id):
        if entity_id in self.keys:
            del self.keys[entity_id]
            self.save_keys()
            logging.warning(f"[{datetime.now(timezone.utc)}] Revoked keys for {entity_id}")

    def renew_keys(self):
        now = datetime.now(timezone.utc)
        for entity_id in list(self.keys):
            created_at = datetime.fromisoformat(self.keys[entity_id]["created_at"])
            if now - created_at > self.expiry_time:
                self.generate_keys(entity_id)
                logging.info(f"[{datetime.now(timezone.utc)}] Renewed keys for {entity_id}")

    def save_keys(self):
        with open(self.storage_file, 'w') as f:
            json.dump(self.keys, f, default=str)

    def load_keys(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                self.keys = json.load(f)


# Usage example
if __name__ == "__main__":
    rkm = RabinKeyManager()
    rkm.generate_keys("HospitalA")
    rkm.generate_keys("ClinicB")

    print("✅ Rabin public keys:")
    print("HospitalA:", rkm.get_public_key("HospitalA"))
    print("ClinicB:", rkm.get_public_key("ClinicB"))

    rkm.renew_keys()
    rkm.revoke_key("ClinicB")
