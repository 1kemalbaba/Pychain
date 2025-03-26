import hashlib
import json
import time
import random
import string


class Wallet:
    def __init__(self):
        
        self.private_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
       
        self.public_key = hashlib.sha256(self.private_key.encode()).hexdigest()

    def sign_transaction(self, transaction_dict):
        """
        Simulate signing a transaction by hashing transaction data with the private key.
        Note: In a real system, use ECDSA or similar cryptographic algorithms.
        """
        tx_string = json.dumps(transaction_dict, sort_keys=True)
        return hashlib.sha256((tx_string + self.private_key).encode()).hexdigest()

    def create_transaction(self, recipient, amount, fee):
        """Create and sign a new transaction."""
        transaction_dict = {
            "sender": self.public_key,
            "recipient": recipient,
            "amount": amount,
            "fee": fee
        }
        signature = self.sign_transaction(transaction_dict)
        return Transaction(self.public_key, recipient, amount, fee, signature)


class Transaction:
    def __init__(self, sender, recipient, amount, fee, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.fee = fee
        self.signature = signature

    def to_dict(self):
        """Convert transaction to a dictionary for serialization."""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data):
        """Create a Transaction object from a dictionary."""
        return cls(data["sender"], data["recipient"], data["amount"], data["fee"], data["signature"])

    def is_valid(self, blockchain):
        """Verify the transaction's signature."""
        if self.sender == "0":  
            return True
        wallet = blockchain.wallets.get(self.sender)
        if not wallet:
            return False
        transaction_dict = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee
        }
        expected_signature = wallet.sign_transaction(transaction_dict)
        return self.signature == expected_signature


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 4  
        self.mining_reward = 10  
        self.block_size_limit = 5  
        self.adjustment_interval = 10  
        self.target_block_time = 10  
        self.wallets = {}  
        self.load_from_file()  

    def create_block(self, previous_hash, nonce, transactions):
        """Create a new block with the given parameters."""
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": transactions,
            "nonce": nonce,
            "previous_hash": previous_hash,
            "difficulty": self.difficulty
        }
        block["hash"] = self.calculate_hash(block)
        self.chain.append(block)
        return block

    def calculate_hash(self, block):
        """Calculate the SHA-256 hash of a block."""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def get_last_block(self):
        """Return the most recent block in the chain."""
        return self.chain[-1]

    def add_transaction(self, transaction):
        """Add a transaction to the pending pool after validation."""
        if not transaction.is_valid(self):
            raise ValueError("Invalid transaction signature")
        
        confirmed_balance = self.get_confirmed_balance(transaction.sender)
        pending_spent = sum(tx.amount + tx.fee for tx in self.pending_transactions if tx.sender == transaction.sender)
        available_balance = confirmed_balance - pending_spent
        if available_balance < transaction.amount + transaction.fee:
            raise ValueError("Insufficient balance")
        self.pending_transactions.append(transaction)

    def proof_of_work(self, previous_hash, transactions):
        """Perform proof-of-work to mine a block."""
        start_time = time.time()
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": transactions,
            "previous_hash": previous_hash,
            "nonce": 0,
            "difficulty": self.difficulty
        }
        while True:
            block["hash"] = self.calculate_hash(block)
            if block["hash"][:self.difficulty] == "0" * self.difficulty:
                elapsed_time = time.time() - start_time
                new_block = self.create_block(previous_hash, block["nonce"], transactions)
               
                if len(self.chain) % self.adjustment_interval == 0:
                    self.adjust_difficulty()
                return new_block
            block["nonce"] += 1

    def adjust_difficulty(self):
        """Adjust mining difficulty based on block time."""
        current_index = len(self.chain) - 1
        previous_adjustment_index = current_index - self.adjustment_interval
        if previous_adjustment_index < 0:
            return
        time_taken = self.chain[current_index]["timestamp"] - self.chain[previous_adjustment_index]["timestamp"]
        expected_time = self.target_block_time * self.adjustment_interval
        if time_taken < expected_time * 0.5:
            self.difficulty += 1
            print(f"Difficulty increased to {self.difficulty}")
        elif time_taken > expected_time * 2:
            self.difficulty = max(1, self.difficulty - 1)
            print(f"Difficulty decreased to {self.difficulty}")

    def mine_block(self, miner_address):
        """Mine a new block, selecting transactions by fee and adding a reward."""
        sorted_txs = sorted(self.pending_transactions, key=lambda tx: tx.fee, reverse=True)
        selected_txs = [tx.to_dict() for tx in sorted_txs[:self.block_size_limit]]
        reward_tx = Transaction("0", miner_address, self.mining_reward, 0)
        selected_txs.insert(0, reward_tx.to_dict())
        last_block = self.get_last_block()
        last_hash = last_block["hash"]
        block = self.proof_of_work(last_hash, selected_txs)
        
        selected_tx_dicts = [tx.to_dict() for tx in self.pending_transactions if tx in sorted_txs[:self.block_size_limit]]
        self.pending_transactions = [tx for tx in self.pending_transactions if tx.to_dict() not in selected_tx_dicts]
        return block

    def get_confirmed_balance(self, address):
        """Calculate balance from confirmed transactions in the chain."""
        balance = 0
        for block in self.chain:
            for tx in block["transactions"]:
                if tx["sender"] == address:
                    balance -= tx["amount"]
                if tx["recipient"] == address:
                    balance += tx["amount"]
        return balance

    def get_balance(self, address):
        """Calculate total balance including pending transactions."""
        balance = self.get_confirmed_balance(address)
        for tx in self.pending_transactions:
            if tx.sender == address:
                balance -= (tx.amount + tx.fee)
            if tx.recipient == address:
                balance += tx.amount
        return balance

    def is_chain_valid(self, chain):
        """Validate an entire chain."""
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block["hash"] != self.calculate_hash(current_block):
                return False
            if current_block["previous_hash"] != previous_block["hash"]:
                return False
            if current_block["hash"][:current_block["difficulty"]] != "0" * current_block["difficulty"]:
                return False
            for tx_dict in current_block["transactions"]:
                tx = Transaction.from_dict(tx_dict)
                if not tx.is_valid(self):
                    return False
        return True

    def replace_chain(self, new_chain):
        """Replace the current chain with a longer, valid chain."""
        if len(new_chain) > len(self.chain):
            if self.is_chain_valid(new_chain):
                self.chain = new_chain
                print("Chain replaced with longer valid chain")
            else:
                print("New chain is invalid")
        else:
            print("New chain is not longer")

    def save_to_file(self, filename="blockchain.json"):
        """Save the blockchain state to a JSON file."""
        data = {
            "chain": self.chain,
            "pending_transactions": [tx.to_dict() for tx in self.pending_transactions],
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward,
            "block_size_limit": self.block_size_limit
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

    def load_from_file(self, filename="blockchain.json"):
        """Load the blockchain state from a JSON file or create a genesis block."""
        try:
            with open(filename, "r") as f:
                data = json.load(f)
                self.chain = data["chain"]
                self.pending_transactions = [Transaction.from_dict(tx) for tx in data["pending_transactions"]]
                self.difficulty = data["difficulty"]
                self.mining_reward = data["mining_reward"]
                self.block_size_limit = data["block_size_limit"]
        except FileNotFoundError:
            genesis_block = {
                "index": 0,
                "timestamp": time.time(),
                "transactions": [],
                "nonce": 0,
                "previous_hash": "0" * 64,
                "difficulty": self.difficulty,
                "hash": self.calculate_hash({
                    "index": 0,
                    "timestamp": time.time(),
                    "transactions": [],
                    "nonce": 0,
                    "previous_hash": "0" * 64,
                    "difficulty": self.difficulty
                })
            }
            self.chain = [genesis_block]
            self.pending_transactions = []

    def register_wallet(self, wallet):
        """Register a wallet with the blockchain for transaction verification."""
        self.wallets[wallet.public_key] = wallet


def main():
    blockchain = Blockchain()
    wallets = {}
    print("Welcome to the Blockchain Masterpiece!")
    while True:
        print("\nMenu:")
        print("1. Create new wallet")
        print("2. Send transaction")
        print("3. Mine block")
        print("4. Check balance")
        print("5. View blockchain")
        print("6. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            wallet = Wallet()
            wallets[wallet.public_key] = wallet
            blockchain.register_wallet(wallet)
            print(f"New wallet created with public key: {wallet.public_key}")
            print(f"Private key (keep this secret!): {wallet.private_key}")

        elif choice == "2":
            sender_pub = input("Enter sender public key: ")
            if sender_pub not in wallets:
                print("Sender wallet not found")
                continue
            recipient_pub = input("Enter recipient public key: ")
            try:
                amount = float(input("Enter amount: "))
                fee = float(input("Enter fee: "))
                sender_wallet = wallets[sender_pub]
                tx = sender_wallet.create_transaction(recipient_pub, amount, fee)
                blockchain.add_transaction(tx)
                print("Transaction added to pending transactions")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "3":
            miner_pub = input("Enter miner public key: ")
            if miner_pub not in wallets:
                print("Miner wallet not found")
                continue
            print("Mining block...")
            block = blockchain.mine_block(miner_pub)
            print(f"Block mined with hash: {block['hash']}")
            blockchain.save_to_file()

        elif choice == "4":
            pub_key = input("Enter public key: ")
            balance = blockchain.get_balance(pub_key)
            print(f"Balance: {balance}")

        elif choice == "5":
            print("\nBlockchain:")
            for block in blockchain.chain:
                print(json.dumps(block, indent=2))

        elif choice == "6":
            print("Saving blockchain and exiting...")
            blockchain.save_to_file()
            break

        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()