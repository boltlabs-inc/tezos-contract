''' Pytezos contract tester

The first part of this script contains functions for calling each of the 
zkchannels contract entrypoints. The functions are written in a way that
matches how they will be used in zeekoe.

The second part of the script tests the functions against either a testnet
or sandbox node. The tests ensure that the origination operation and 
entrypoint calls are made successfully, and that the contract behaves as
expected.

To run the tests the --network argument must be provided with either 
'testnet' to connect to a public testnet node, or the uri of the tezos node
RPC.
'''

import argparse
import json
from pytezos import pytezos, ContractInterface
from pprint import pprint
import requests

###################### Start of functions used by zeekoe ######################

def originate(
uri,
cust_addr, merch_addr,
cust_acc,
merch_pubkey,
channel_id,
merch_g2, merch_y2s, merch_x2,
cust_funding, merch_funding,
min_confirmations, 
self_delay,
revocation_lock
):
    # Customer pytezos interface
    cust_py = pytezos.using(key=cust_acc, shell=uri)

    initial_storage = {"cid": channel_id, 
    "customer_address": cust_addr, 
    "customer_balance": cust_funding, 
    "delay_expiry": "1970-01-01T00:00:00Z", 
    "g2": merch_g2,
    "merchant_address": merch_addr, 
    "merchant_balance": merch_funding, 
    "merchant_public_key": merch_pubkey, 
    "y2s_0": merch_y2s[0],
    "y2s_1": merch_y2s[1],
    "y2s_2": merch_y2s[2],
    "y2s_3": merch_y2s[3],
    "y2s_4": merch_y2s[4],
    "x2": merch_x2,
    "revocation_lock": revocation_lock, 
    "self_delay": self_delay, 
    "status": 0}

    # Originate main zkchannel contract
    out = cust_py.origination(script=main_code.script(initial_storage=initial_storage)).autofill().sign().send(min_confirmations=min_confirmations)
    
    # Get address, status, and level of main zkchannel contract
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    contract_id = contents["metadata"]["operation_result"]["originated_contracts"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"contract_id": contract_id, "status": status, "level": level, "op_info": op_info}

def add_customer_funding(
cust_acc,
contract_id,
cust_funding,
min_confirmations
):
    # Customer pytezos interface
    cust_py = pytezos.using(key=cust_acc, shell=uri)

    # Customer zkchannel contract interface
    cust_ci = cust_py.contract(contract_id)

    # Call the addCustFunding entrypoint
    out = cust_ci.addCustFunding().with_amount(cust_funding).send(min_confirmations=min_confirmations)

    # Get status and level of the addCustFunding operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def add_merchant_funding(
merch_acc,
contract_id,
merch_funding,
min_confirmations
):
    # Merchant pytezos interface
    merch_py = pytezos.using(key=merch_acc, shell=uri)

    # Merchant zkchannel contract interface
    merch_ci = merch_py.contract(contract_id)

    # Call the addMerchFunding entrypoint
    out = merch_ci.addMerchFunding().with_amount(merch_funding).send(min_confirmations=min_confirmations)

    # Get status and level of the addMerchFunding operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def cust_close(
cust_acc,
contract_id,
customer_balance, merchant_balance,
sigma1, sigma2,
revocation_lock,
min_confirmations,
):
    # Customer pytezos interface
    cust_py = pytezos.using(key=cust_acc, shell=uri)

    # Customer zkchannel contract interface
    cust_ci = cust_py.contract(contract_id)

    # Set the storage for the operation
    close_storage = {
        "customer_balance": int(customer_balance),
        "merchant_balance": int(merchant_balance),
        "revocation_lock": revocation_lock,
        "sigma1": sigma1,
        "sigma2": sigma2
    }

    # Call the custClose entrypoint
    out = cust_ci.custClose(close_storage).send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def cust_claim(
cust_acc,
contract_id,
min_confirmations,
):
    # Customer pytezos interface
    cust_py = pytezos.using(key=cust_acc, shell=uri)

    # Customer zkchannel contract interface
    cust_ci = cust_py.contract(contract_id)

    # Call the custClaim entrypoint
    out = cust_ci.custClaim().send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def reclaim_funding(
cust_acc,
contract_id,
min_confirmations,
):
    # Customer pytezos interface
    cust_py = pytezos.using(key=cust_acc, shell=uri)

    # Customer zkchannel contract interface
    cust_ci = cust_py.contract(contract_id)

    # Call the reclaimFunding entrypoint
    out = cust_ci.reclaimFunding().send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def expiry(
merch_acc,
contract_id,
min_confirmations,
):
    # Merchant pytezos interface
    merch_py = pytezos.using(key=merch_acc, shell=uri)

    # Merchant zkchannel contract interface
    merch_ci = merch_py.contract(contract_id)

    # Call the expiry entrypoint
    out = merch_ci.expiry().send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def merch_claim(
merch_acc,
contract_id,
min_confirmations,
):
    # Merchant pytezos interface
    merch_py = pytezos.using(key=merch_acc, shell=uri)

    # Merchant zkchannel contract interface
    merch_ci = merch_py.contract(contract_id)

    # Call the merchClaim entrypoint
    out = merch_ci.merchClaim().send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def merch_dispute(
merch_acc,
contract_id,
revocation_secret,
min_confirmations,
):
    # Merchant pytezos interface
    merch_py = pytezos.using(key=merch_acc, shell=uri)

    # Merchant zkchannel contract interface
    merch_ci = merch_py.contract(contract_id)

    # Call the merchDispute entrypoint
    out = merch_ci.merchDispute(revocation_secret).send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

def mutual_close(
cust_acc,
contract_id,
customer_balance, merchant_balance,
mutual_close_signature,
min_confirmations,
):
    # Customer pytezos interface
    cust_py = pytezos.using(key=cust_acc, shell=uri)

    # Customer zkchannel contract interface
    cust_ci = cust_py.contract(contract_id)

    # Set the storage for the operation
    mutual_close_storage = {
        "customer_balance": int(customer_balance),
        "merchant_balance": int(merchant_balance),
        "merchSig": mutual_close_signature
    }

    # Call the mutualClose entrypoint
    out = cust_ci.mutualClose(mutual_close_storage).send(min_confirmations=min_confirmations)

    # Get status and level of the operation
    op_info = pytezos.using(shell=uri).shell.blocks[-20:].find_operation(out.hash())
    contents = op_info["contents"][0]
    status = contents["metadata"]["operation_result"]["status"]
    level = 1 # TODO: get the level where the operation was confirmed

    return {"status": status, "level": level, "op_info": op_info}

####################### End of functions used in zeekoe #######################
###############################################################################

def read_json_file(json_file):
    f = open(json_file)
    s = f.read()
    f.close()
    return json.loads(s)

class colors:
     PURPLE = '\033[95m'
     GREEN = '\033[92m'
     ENDC = '\033[0m'

def print_header(msg):
    print(f"{colors.PURPLE}{msg}{colors.ENDC}")

def activate_and_reveal(account):
    ''' 
    If it's the first time using the testnet account, 
    it will need to be activated and the pubkey will need
    to be revealed. This function will perform both steps
    '''
    pytezos_interface = pytezos.using(key=account)
    try:
        print(f"Activating {account}")
        pytezos_interface.activate_account().fill().sign().send()
    except:
        print(f"Account already activated")
    try:
        print(f"Revealing {account} pubkey")
        pytezos_interface.reveal().autofill().sign().send()
    except:
        print(f"Pubkey already revealed")

class FeeTracker:
    def __init__(self):
        self.fees = []
        # get protocol constants from tzstats (mainnet)
        r =requests.get('https://api.tzstats.com/explorer/config/head')
        # get byte cost for the current protocol
        self.byte_cost = r.json()['cost_per_byte']
        # get size in bytes of creating a new address
        self.origination_size = r.json()['origination_size'] 

    def add_result(self, op_name, result):
        """Add the fees from the operation costs to self.fees"""
        costs = {}
        op_metadata = result["contents"][0]["metadata"]["operation_result"]
        costs["gas"] = int(op_metadata["consumed_gas"])
        costs["fee"] = int(result['contents'][0]['fee'])
        storage_bytes = 0
        if "paid_storage_size_diff" in op_metadata:
            storage_bytes = int(op_metadata["paid_storage_size_diff"])
        costs["storage_bytes"] = storage_bytes
        costs["storage_cost"] = int(storage_bytes) * self.byte_cost 
        costs["total_cost"] = costs["fee"] + costs["storage_cost"]
        # "originate" operation incurs a fixed allocation_fee for creating a new contract address
        if op_name == "originate":
            costs["allocation_fee"] = self.byte_cost * self.origination_size
            costs["total_cost"] += costs["allocation_fee"]
        self.fees.append({op_name:costs})

    def print_fees(self):
        pprint(self.fees)
    
    def save_json(self):
        with open('fees.json', 'w') as outfile:
            json.dump(self.fees, outfile, indent=4)

def test_dispute(revocation_secret, revocation_lock):
    print_header("Scenarixo test_dispute")

    origination_op = originate(uri,
        cust_addr, merch_addr,
        cust_acc,
        merch_pubkey,
        channel_id,
        merch_g2, merch_y2s, merch_x2,
        cust_funding, merch_funding,
        min_confirmations, 
        self_delay,
        revocation_lock
        )

    op_info = merch_dispute(
        merch_acc,
        origination_op["contract_id"],
        revocation_secret,
        min_confirmations
        )["op_info"]

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--network", type=str, required=True, help="either 'testnet' or the RPC node uri")
parser.add_argument("-s", "--self_delay", type=int, default=1, help="the value for self_delay in seconds")
parser.add_argument("-m", "--min_confirmations", type=int, default=1, help="the minimum number of required confirmations for an operation")
args = parser.parse_args()

if args.network == "testnet":
    uri = "https://rpc.tzkt.io/granadanet"
else:
    uri = args.network
min_confirmations = args.min_confirmations
self_delay = args.self_delay

# Define paths for all the files that will be used in the tests.
establish_file = "sample_files/le-establish.json"
close_file = "sample_files/le-close.json"
dispute_file = "sample_files/le-dispute.json"
tezos_account1 = "sample_files/tz1iKxZpa5x1grZyN2Uw9gERXJJPMyG22Sqp.json"
tezos_account2 = "sample_files/tz1bXwRiFvijKnZYUj9J53oYE3fFkMTWXqNx.json"
zkchannel_contract = "../zkchannels-contract/zkchannel_contract.json"

# Load establish parameters from establish.json
establish_json = read_json_file(establish_file)

# Load variables from establish_json
merch_ps_pk = establish_json.get("merchant_ps_public_key")
channel_id = establish_json.get("channel_id")
cust_funding = establish_json.get("customer_deposit")
merch_funding = establish_json.get("merchant_deposit")
# Merchant's PS pubkey
merch_g2 = merch_ps_pk.get("g2")
merch_y2s = merch_ps_pk.get("y2s")
merch_x2 = merch_ps_pk.get("x2")

# Load variables from close_json
cust_close_json = read_json_file(close_file)
cs = cust_close_json.get("closing_signature")
sigma1, sigma2 = cs.get("sigma1"), cs.get("sigma2")
revocation_lock = cust_close_json.get("revocation_lock")
customer_balance = cust_close_json.get("customer_balance")
merchant_balance = cust_close_json.get("merchant_balance")

# Load revocation secret from dispute_json
dispute_json = read_json_file(dispute_file)
revocation_secret = dispute_json.get("revocation_secret")

# Load tezos account variables
cust_acc = tezos_account1
cust_addr = read_json_file(cust_acc)["pkh"]
merch_acc = tezos_account2
merch_addr = read_json_file(merch_acc)["pkh"]

# Load the zkchannels contract
f = open(zkchannel_contract,)
data = json.load(f)
main_code = ContractInterface.from_micheline(data)

# Query the blockchain to get the merchant's and customer's public keys
merch_py = pytezos.using(key=merch_acc, shell=uri)
merch_pubkey = merch_py.key.public_key()
cust_py = pytezos.using(key=cust_acc, shell=uri)

# # Initialize the feetracker, used to record gas and storage costs of operations.
# feetracker = FeeTracker()

succeeding_revlock_pairs = (
    (
        "0x6b7444c8ae54df16e75f30c84f96146ca7e80a36a72f6ccf4125ca3ccfb4115e",
        "0x5bda64ebfecaa0030a07af64bcd151e72ad9f8fc21b802094d6ceace6b28e373"
    ),
    (
        "0xed593cc537cb018bc8ed016b800a69e84aace5c2a499f43d7423193261a96c4b",
        "0x0cc0f93979e3a1bbf3e17412347949c93823cda123134ff02b4fccb1be0f0830"
    ),
    (
        "0x53411836bca769d5af3fe207b95a2575c776eac6ab2e25e8c46bd77d882c4f11",
        "0x73f4866d6ac7775de7533a6430b9ba2a2d66642ee4fe415e971d0d264b16b10a"
    ),
)

failing_revlock_pairs = (
    (
        "0xdc2aff71a1a2975e14301e50844064a0afb2a593ccc1460e4a0dd5bb36a7d744", "0xdd6ecbe06960532183ad92dc095793ba937de478a6b14fbb24174c536f50ae4d"
    ),
    (
        "0x8400711a8290c6788a58d1cf5c97751b87bf898d448e923ce6fa9f5418ea0c17", "0x7faacce83438d951b9d9917c533c50620cd37f39714d5229091436e43663200b"
    ),
    (
        "0xe998f4797d45dfc50e6f60127c5d49a704ad5bcaff8a85d9389e7e237d64ae5f", "0x54e1c3d796ed39ff9f42190a2dea74331a173dd1395d946e06269148cc9c372f"
    ),
)

for (rev_secret, rev_lock) in succeeding_revlock_pairs:
    test_dispute(rev_secret, rev_lock)

print("Tests finished!")