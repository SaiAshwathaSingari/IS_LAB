from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import time


class KeyManagementSystem:
    def __init__(self):
        # Store RSA keys per subsystem
        self.subsystems = {}

    def generate_rsa_keys(self, subsystem_id):
        """
        Generate RSA key pair for the given subsystem and store it.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.subsystems[subsystem_id] = {
            'private_key': private_key,
            'public_key': public_key,
            'created_at': time.time()
        }
        print(f"RSA keys generated for {subsystem_id}")

    def get_public_key(self, subsystem_id):
        """
        Return the public key for the given subsystem.
        """
        if subsystem_id in self.subsystems:
            return self.subsystems[subsystem_id]['public_key']
        else:
            raise ValueError(f"No keys found for subsystem {subsystem_id}")

    def revoke_key(self, subsystem_id):
        """
        Remove keys for a given subsystem.
        """
        if subsystem_id in self.subsystems:
            del self.subsystems[subsystem_id]
            print(f"Keys revoked for {subsystem_id}")
        else:
            print(f"No keys found to revoke for {subsystem_id}")

    def renew_key(self, subsystem_id):
        """
        Renew RSA key for the subsystem by generating a new key pair.
        """
        self.generate_rsa_keys(subsystem_id)
        print(f"Keys renewed for {subsystem_id}")


class DiffieHellmanSession:
    def __init__(self, parameters):
        """
        Initialize Diffie-Hellman session with shared parameters.
        """
        self.parameters = parameters
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def generate_shared_key(self, peer_public_key):
        """
        Generate a shared key using own private key and peer's public key.
        """
        shared_key = self.private_key.exchange(peer_public_key)
        # Derive a symmetric key from shared key material using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure communication',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key


def main():
    # Step 1: Initialize the Key Management System and generate RSA keys
    kms = KeyManagementSystem()
    kms.generate_rsa_keys("FinanceSystem")   # System A
    kms.generate_rsa_keys("HRSystem")        # System B
    kms.generate_rsa_keys("SupplyChainSystem")  # System C

    # Step 2: Generate Diffie-Hellman parameters ONCE and share across all systems
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    # Step 3: Create DH sessions for two systems that want to communicate
    dh_session_finance = DiffieHellmanSession(dh_parameters)
    dh_session_hr = DiffieHellmanSession(dh_parameters)

    # Step 4: Exchange public keys and generate shared secret keys
    shared_key_finance = dh_session_finance.generate_shared_key(dh_session_hr.public_key)
    shared_key_hr = dh_session_hr.generate_shared_key(dh_session_finance.public_key)

    # Step 5: Verify that both shared keys are equal
    assert shared_key_finance == shared_key_hr, "Shared keys do not match!"
    print("Secure shared key established b0etween FinanceSystem and HRSystem.")

    # Demonstrate key revocation and renewal
    kms.revoke_key("SupplyChainSystem")
    kms.renew_key("HRSystem")


if __name__ == "__main__":
    main()
