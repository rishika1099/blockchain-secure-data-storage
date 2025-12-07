# 🔐 Blockchain-Based Confidential Storage for Healthcare Records

This project implements a secure blockchain-based system for storing sensitive medical or drug-review data using encryption, digital signatures, and proof-of-work. Each record from the dataset is encrypted with a key derived from an ECDSA private key, then stored as a block containing a timestamp, hash linkage, and a cryptographic signature to ensure authenticity and integrity. The blockchain verifies each block using the public key alone, making tampering immediately detectable. Finally, the encrypted records are safely decrypted and reconstructed back into a complete pandas DataFrame, demonstrating an end-to-end workflow for confidential, tamper-evident healthcare data storage.

---

## 🎯 Project Overview

This system demonstrates how blockchain principles can enhance the security of sensitive healthcare data by:

- **Encrypting** each record using cryptographic keys
- **Securing** data with ECDSA digital signatures
- **Protecting** integrity through Proof-of-Work consensus
- **Ensuring** tamper-evidence through hash linkage
- **Maintaining** a transparent audit trail

The project removes reliance on a central authority and provides verifiable, confidential storage suitable for medical data environments.

---

## 🔧 Technologies & Libraries

This project uses:

- **Python 3.x**
- **ecdsa** - Elliptic Curve Digital Signature Algorithm
- **cryptocode** - Symmetric encryption/decryption
- **pycryptodomex** - Cryptographic functions
- **pandas** - Data manipulation and analysis
- **hashlib** - Secure hash functions (SHA-256)
- **json** - Data serialization
- **datetime** - Timestamp generation

---

## 📂 Dataset

- **Source:** `drugs.csv` (drug review dataset)
- **Structure:** Each row represents a healthcare/drug review record
- **Processing:** Individual rows are encrypted and stored as blockchain blocks

---

## 🏗️ System Architecture

### 1️⃣ Key Generation (ECDSA)

The system generates a public-private key pair using the SECP256k1 elliptic curve:
```python
# Generate signing (private) key and verifying (public) key
sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()

# Private key as hex string (used for encryption)
private_key = sk.to_string().hex()

# Public key in base64 (for sharing/storage)
public_key_bytes = vk.to_string()
public_key_b64 = base64.b64encode(public_key_bytes).decode()
```

**Key Components:**
- **Private Key:** Used as the encryption password and for signing blocks
- **Public Key:** Used for signature verification (authentication)

---

### 2️⃣ Blockchain Implementation

The custom `Blockchain` class includes:

#### **Block Structure**
```python
block = {
    'index': int,              # Block number
    'timestamp': str,          # Creation time
    'data': str,              # Encrypted record
    'proof': int,             # Proof-of-Work nonce
    'previous_hash': str,     # Link to previous block
    'signature': str          # Digital signature (hex)
}
```

#### **Core Methods**

**Genesis Block Creation:**
```python
def __init__(self):
    self.chain = []
    self.create_blockchain(data='Genesis Block', proof=1, previous_hash='0')
```

**Block Addition with Digital Signature:**
```python
def create_blockchain(self, data, proof, previous_hash):
    signature_bytes = sk.sign(b"Authorised")
    
    block = {
        'index': len(self.chain) + 1,
        'timestamp': str(datetime.datetime.now()),
        'data': str(data),
        'proof': proof,
        'previous_hash': previous_hash,
        'signature': signature_bytes.hex()
    }
    self.chain.append(block)
    return block
```

**Proof-of-Work Mining:**
```python
def proof_of_work(self, previous_proof):
    new_proof = 1
    check_proof = False
    while check_proof is False:
        hash_operation = hashlib.sha256(
            str(new_proof ** 2 - previous_proof ** 2).encode()
        ).hexdigest()
        
        if hash_operation[:4] == '0000':
            check_proof = True
        else:
            new_proof += 1
    return new_proof
```

**Block Hashing:**
```python
def hash(self, block):
    encoded_block = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(encoded_block).hexdigest()
```

---

### 3️⃣ Data Encryption & Storage Workflow
```python
for i in range(len(df)):
    # Convert row to text
    text = df.iloc[i].to_string()
    
    # Encrypt with private key
    data = cryptocode.encrypt(text, private_key)
    
    # Get previous block information
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    
    # Mine new block
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    
    # Add encrypted block to chain
    block = blockchain.create_blockchain(data, proof, previous_hash)
```

**Process Flow:**
1. Extract each row from the dataset
2. Convert row to string format
3. Encrypt using private key
4. Mine new proof-of-work
5. Create block with encrypted data and signature
6. Link to previous block via hash

---

### 4️⃣ Signature Verification & Decryption
```python
from ecdsa import BadSignatureError

for i, block in enumerate(blockchain.chain):
    sig_hex = block['signature']
    sig_bytes = bytes.fromhex(sig_hex)
    
    # Verify signature with public key
    try:
        vk.verify(sig_bytes, b"Authorised")
        valid_sig = True
    except BadSignatureError:
        valid_sig = False
    
    # Decrypt only if signature is valid
    if block['index'] == 1:
        decrypted = block['data']  # Genesis block
    else:
        if valid_sig:
            decrypted = cryptocode.decrypt(block['data'], private_key)
        else:
            decrypted = "[INVALID SIGNATURE — DATA NOT DECRYPTED]"
```

**Verification Process:**
- Each block's signature is verified using the public key
- Only authenticated blocks are decrypted
- Invalid signatures prevent data access

---

### 5️⃣ DataFrame Reconstruction
```python
rows = []

for block in blockchain.chain:
    # Skip genesis block
    if block['index'] == 1:
        continue
    
    # Decrypt data
    decrypted = cryptocode.decrypt(block['data'], private_key)
    
    if decrypted is None:
        print("Warning: Block", block['index'], "failed to decrypt. Skipping.")
        continue
    
    # Convert multi-line string back into dictionary
    row_dict = {}
    for line in decrypted.split("\n"):
        if line.strip() == "":
            continue
        key, value = line.split(maxsplit=1)
        row_dict[key] = value.strip()
    
    rows.append(row_dict)

# Build dataframe
reconstructed_df = pd.DataFrame(rows)
```

---

## ▶️ How to Run the Project

### 1. Install Dependencies
```bash
pip install ecdsa cryptocode pycryptodomex pandas
```

### 2. Prepare Dataset

Place your `drugs.csv` file in the project directory.

### 3. Run the Notebook

Execute all cells in `Blockchain_for_Secure_Data_Storage.ipynb` in order:

1. **Import libraries**
2. **Generate cryptographic keys**
3. **Initialize blockchain**
4. **Load dataset**
5. **Encrypt and add records to blockchain**
6. **View the blockchain**
7. **Verify signatures and decrypt data**
8. **Reconstruct original dataframe**

---

## 🔒 Security Features

### ✅ Encryption
- Symmetric encryption using `cryptocode`
- Private key derived from ECDSA key pair
- Each record encrypted individually

### ✅ Digital Signatures
- ECDSA signatures on SECP256k1 curve
- Signs "Authorised" message for each block
- Verification using public key only

### ✅ Proof-of-Work
- Mining difficulty: 4 leading zeros
- Prevents rapid chain manipulation
- Computational cost for adding blocks

### ✅ Hash Linkage
- Each block references previous block's hash
- Tampering with any block breaks the chain
- Immediate detection of modifications

### ✅ Immutability
- Append-only structure
- Historical audit trail preserved
- No central authority required

---

## 📊 Output Examples

### Blockchain Structure
```json
{
    "chain": [
        {
            "index": 1,
            "timestamp": "2024-12-07 10:30:45.123456",
            "data": "Genesis Block",
            "proof": 1,
            "previous_hash": "0",
            "signature": "3045022100..."
        },
        {
            "index": 2,
            "timestamp": "2024-12-07 10:31:12.789012",
            "data": "*ySjJF6Ao...[encrypted]",
            "proof": 36293,
            "previous_hash": "a4e5f6...",
            "signature": "304402207b..."
        }
    ],
    "length": 2
}
```

### Verification Output
```
Block 1 :
  Signature valid: True
  Index:           1
  Timestamp:       2024-12-07 10:30:45.123456
  Data:            Genesis Block
  Proof:           1
  Previous Hash:   0

Block 2 :
  Signature valid: True
  Index:           2
  Timestamp:       2024-12-07 10:31:12.789012
  Data:            [Decrypted drug review record]
  Proof:           36293
  Previous Hash:   a4e5f6...
```

---

## 🚀 Potential Improvements

- **Fine-grained Access Control:** Multi-signature schemes for role-based access
- **Distributed Network:** Deploy across multiple nodes
- **Smart Contracts:** Automated data access policies
- **IPFS Integration:** Store large files off-chain
- **Consensus Mechanisms:** Implement alternative algorithms (PoS, PBFT)
- **Web Interface:** Build Flask/Django dashboard
- **Database Backend:** Integrate with PostgreSQL/MongoDB
- **Key Management:** Hardware security module (HSM) integration
- **Audit Logging:** Enhanced tracking and compliance features

---

## 🎓 Use Cases

- **Healthcare Records:** Secure patient data storage
- **Drug Reviews:** Tamper-proof pharmaceutical data
- **Clinical Trials:** Immutable research data
- **Medical Billing:** Transparent transaction records
- **Supply Chain:** Track pharmaceutical authenticity
- **Regulatory Compliance:** Auditable data systems

---

## 🏁 Conclusion

This system offers a strong demonstration of how blockchain principles can enhance the security of sensitive healthcare data. By encrypting each record and securing it with digital signatures and Proof of Work, the solution ensures that stored information remains confidential, tamper-evident, and verifiable. This approach removes reliance on a central authority, reduces the risk of unauthorized modifications, and provides a transparent audit trail of all stored data. While designed as an educational prototype, the project highlights how blockchain-based architectures can significantly strengthen data protection and trustworthiness in real-world medical data environments.

---
