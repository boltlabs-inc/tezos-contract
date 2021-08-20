# Example usage:
# python3 zkchannel_edo2net_broadcaster.py --contract=../zkchannels-contract/zkchannel_contract.tz --cust=sample_files/tz1S6eSPZVQzHyPF2bRKhSKZhDZZSikB3e51.json --merch=sample_files/tz1VcYZwxQoyxfjhpNiRkdCUe5rzs53LMev6.json --establish=sample_files/out.5f0b6efabc46808589acc4ffcfa9e9c8412cc097e45d523463da557d2c675c67.establish.json --cust-close=sample_files/out.5f0b6efabc46808589acc4ffcfa9e9c8412cc097e45d523463da557d2c675c67.close.json

import argparse
from pprint import pprint
from pytezos import pytezos
from pytezos import Contract
from pytezos import ContractInterface
import json
class colors:
     PURPLE = '\033[95m'
     GREEN = '\033[92m'
     ENDC = '\033[0m'

def print_header(msg):
    print(f"{colors.PURPLE}{msg}{colors.ENDC}")

def print_green(msg):
    print(f"{colors.GREEN}{msg}{colors.ENDC}")

def read_json_file(json_file):
    f = open(json_file)
    s = f.read()
    f.close()
    return json.loads(s)

def add_hex_prefix(s):
    if s[:2] == "0x":
        return s
    return "0x" + s

def convert_to_little_endian(s):
    t = s
    if s[:2] == "0x":
        t = s[2:]
    return bytes.fromhex(t)[::-1].hex()

def get_cust_close_token(data):
    merch_pk = data.get("merch_pk")
    pubkey = {}
    for k,v in merch_pk.items():
        pubkey[k] = "0x" + str(v)
    m = data.get("message")
    message = [ 
        add_hex_prefix(m["channel_id"]), 
        add_hex_prefix(m["rev_lock"]),
        add_hex_prefix(int(m["cust_bal"]).to_bytes(32, 'little').hex()),
        add_hex_prefix(int(m["merch_bal"]).to_bytes(32, 'little').hex()),
        add_hex_prefix(m["close"]),
    ]
    sig = data.get("signature")
    s1 = add_hex_prefix(sig.get("s1"))
    s2 = add_hex_prefix(sig.get("s2"))
    signature = [s1, s2]
    # print("Merch PK: %s" % pubkey)
    # print("Message: %s" % message)
    # print("Signature: %s" % signature)
    return (pubkey, message, signature)

def convert_mt_to_tez(balance):
    return str(int(balance) /1000000)

class FeeTracker:
    def __init__(self):
        self.fees = []
    
    def add_result(self, op_name, result):
        """Add the fees of the fees from operation result to self.fees"""
        fee = int(result['contents'][0]['fee'])
        storage_bytes = int(result['contents'][0]['storage_limit'])
        storage_cost = int(storage_bytes) * 250 # 250 mutez per storage_bytes byte on edo
        gas = int(result["contents"][0]["metadata"]["operation_result"]["consumed_gas"])
        total_cost = fee + storage_cost
        fee = {"total_cost":total_cost, "fee":fee, "storage_bytes":storage_bytes, "storage_cost":storage_cost, "gas":gas}
        self.fees.append({op_name:fee})

    def print_fees(self):
        pprint(self.fees)

def add_cust_funding(ci, amt):
    print_green(f"Adding funds ({amt})")
    out = ci.addCustFunding().with_amount(amt).send(min_confirmations=1)
    print_green(f"addCustFunding ophash: {out.hash()}")
    opg = pytezos.shell.blocks[-20:].find_operation(out.hash())
    return opg

def add_merch_funding(ci, amt):
    print_green(f"Adding funds ({amt})")
    out = ci.addMerchFunding().with_amount(amt).send(min_confirmations=1)
    print_green(f"addMerchFunding ophash: {out.hash()}")
    opg = pytezos.shell.blocks[-20:].find_operation(out.hash())
    return opg

def originate(cust_py, init_params, cust_funding, merch_funding):
    # Create initial storage for main zkchannel contract
    merch_ps_pk = init_params.get("merchant_ps_public_key")
    close_scalar_bytes = init_params.get("close_scalar_bytes")
    channel_id = init_params.get("channel_id")

    # Merchant's PS pubkey, used for verifying the merchant's signature in custClose.
    g2 = merch_ps_pk.get("g2")
    y2s = merch_ps_pk.get("y2s")
    x2 = merch_ps_pk.get("x2")
    
    initial_storage = {'cid': channel_id, 
    'close_flag': close_scalar_bytes,
    'context_string': "zkChannels mutual close",
    'custAddr': cust_addr, 
    'custBal':cust_funding,  
    'custPk': cust_pubkey, 
    'delayExpiry': '1970-01-01T00:00:00Z', 
    'g2':g2,
    'merchAddr': merch_addr, 
    'merchBal': merch_funding, 
    'merchPk': merch_pubkey, 
    'y2s_0': y2s[0],
    'y2s_1': y2s[1],
    'y2s_2': y2s[2],
    'y2s_3': y2s[3],
    'y2s_4': y2s[4],
    'x2': x2,
    'revLock': '0x00', 
    'selfDelay': 3, 
    'status': 0}

    # Originate main zkchannel contract
    print_green("Originate main zkChannel contract")
    out = cust_py.origination(script=main_code.script(initial_storage=initial_storage)).autofill().sign().send(min_confirmations=1)
    print_green(f"Originate zkChannel ophash: {out.hash()}")
    # Get address of main zkchannel contract
    opg = pytezos.shell.blocks[-20:].find_operation(out.hash())
    main_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]
    print_green(f"zkChannel contract address: {main_id}")
    return opg, main_id

def cust_close(ci, init_params, cust_close_data):
    # Form cust close storage
    cs = cust_close_data.get("closing_signature")
    sigma1, sigma2 = cs.get("sigma1"), cs.get("sigma2")
    revocation_lock = cust_close_data.get("revocation_lock")

    cust_balance = convert_mt_to_tez(cust_close_data.get("customer_balance"))
    merch_balance = convert_mt_to_tez(cust_close_data.get("merchant_balance"))

    close_storage = {
        "custBal": cust_balance,
        "merchBal": merch_balance,
        "revLock": revocation_lock,
        "sigma1": sigma1,
        "sigma2": sigma2
    }

    print_green("Broadcasting Cust Close")
    out = ci.custClose(close_storage).send(min_confirmations=1)
    print_green(f"Cust Close ophash: {out.hash()}")
    opg = pytezos.shell.blocks[-20:].find_operation(out.hash())
    return opg

def merch_dispute(ci, entrypoint, rev_secret):
    print_green('Broadcasting {entrypoint}')
    cmd = 'ci.{e}(\"{r}\").send(min_confirmations=1)'.format(e=entrypoint, r=rev_secret)
    print_green(f"{entrypoint} ophash: {out.hash()}")
    opg = pytezos.shell.blocks[-20:].find_operation(out.hash())
    return opg

def entrypoint_no_args(ci, entrypoint):
    print_green(f"Broadcasting {entrypoint}")
    cmd = 'ci.{}().send(min_confirmations=1)'.format(entrypoint)
    out = eval(cmd)
    print_green(f"{entrypoint} ophash: {out.hash()}")
    opg = pytezos.shell.blocks[-20:].find_operation(out.hash())
    return opg

def test_custclaim(feetracker, cust_py, merch_py, cust_close_json, establish_params):
    '''
    Customer creates a single funded contract then initiates a unilateral customer closure.
    Entrypoints tested: 'addCustFunding', 'custClose', 'custClaim'.
    '''
    print_header("Scenario test_custclaim: origination -> cust_funding -> cust_close -> cust_claim")

    # A single-funded channel is originated where the customer's initial balances (in mutez) is:
    cust_funding=establish_json.get("customer_deposit")
    merch_funding=establish_json.get("merchant_deposit")

    out, contract_id = originate(cust_py, establish_params, cust_funding, merch_funding)
    feetracker.add_result('originate', out) # feetracker is used to track fees for benchmarking purposes 

    # Set the contract interfaces for cust
    cust_ci = cust_py.contract(contract_id)

    # add customer's balance to the contract using 'addCustFunding' entrypoint
    out = add_cust_funding(cust_ci, cust_funding)
    feetracker.add_result('addCustFunding', out)

    # customer initates unilateral closure using 'custClose' entrypoint. 
    # The merchant's closing signature is included in 'cust_close_json'.
    out = cust_close(cust_ci, establish_params, cust_close_json)
    feetracker.add_result('custClose', out)
    out = entrypoint_no_args(cust_ci, 'custClaim')
    feetracker.add_result('custClaim', out)


def test_dispute(feetracker, cust_py, merch_py, cust_close_json, establish_params):
    '''
    First the merchant initiates a unilateral closure, then the customer closes on an outdated state and is punished by the merchant.
    Entrypoints tested: 'addCustFunding', 'expiry', 'custClose', 'merchDispute'.
    '''
    print_header("Scenario test_dispute: origination -> cust_funding -> merch_funding -> expiry -> cust_close -> merch_dispute")
    # A single-funded channel is originated where the customer's initial balances (in mutez) is:
    cust_funding=establish_json.get("customer_deposit")
    merch_funding=establish_json.get("merchant_deposit")

    out, contract_id = originate(cust_py, establish_params, cust_funding, merch_funding)
    
    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(contract_id)
    merch_ci = merch_py.contract(contract_id)

    # customer funds their side of the contract with the same amount as their initial balance
    out = add_cust_funding(cust_ci, cust_funding)

    # Merchant initiates closure by calling the 'expiry' entrypoint.
    out = entrypoint_no_args(merch_ci, 'expiry')

    # Customer initiates closure in response to 'expiry'.
    out = cust_close(cust_ci, establish_params, cust_close_json)

    # TODO: Add merch dispute scenario (needs a valid rev_secret)
    # # Here, we simulate the customer closing on an old state. 
    # # The merchant views the contract storage and checks if 'rev_lock' has been seen before. 
    # # rev_lock has been seen, the merchant will punish the customer by calling 'merchDispute' and providing the revocation secret.
    # # If the secret is valid, the contract will give the total balance to the merchant.
    # rev_secret = add_hex_prefix(merch_close_json['rev_secret'])
    # out = merch_dispute(merch_ci, 'merchDispute', rev_secret)
    # feetracker.add_result('merchDispute', out)

def test_merchClaim(feetracker, cust_py, merch_py, cust_close_json, establish_params):
    '''
    Tests the 'merchClaim' entrypoint.
    'merchClaim' is used by the merchant to claim the total channel balance if the customer fails to respond to the 'expiry' call.
    Entrypoints tested: 'addCustFunding', 'reclaimFunding'.
    '''
    print_header("Scenario test_merchClaim: origination -> cust_funding -> reclaim_funding")
   
    # A single-funded channel is originated where the customer's initial balances (in mutez) is:
    cust_funding=establish_json.get("customer_deposit")
    merch_funding=establish_json.get("merchant_deposit")

    out, contract_id = originate(cust_py, establish_params, cust_funding, merch_funding)

    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(contract_id)
    merch_ci = merch_py.contract(contract_id)

    # add customer's balance to the contract using 'addCustFunding' entrypoint
    out = add_cust_funding(cust_ci, cust_funding)
    feetracker.add_result('addCustFunding', out)

    # Merchant initiates closure by calling the 'expiry' entrypoint.
    out = entrypoint_no_args(merch_ci, 'expiry')

    # If the customer has not broadcasted 'custClose' in response to 'expiry', the merchant can claim the full channel balance with 'merchClaim'.
    out = entrypoint_no_args(merch_ci, 'merchClaim')
    feetracker.add_result('merchClaim', out)

def test_dualfund(feetracker, cust_py, merch_py, cust_close_json, establish_params):
    '''
    Tests the 'addCustFunding' and 'addMerchFunding' entrypoints.
    '''
    print_header("Scenario test_dualfund: origination -> cust_funding -> merch_funding -> reclaim_funding")

    # Create a dual-funded channel. If the establish_json is for a single funded channel, use the customer_deposit for the merchant so that it's non-zeo
    cust_funding=establish_json.get("customer_deposit")
    if establish_json.get("merchant_deposit") == 0:
        merch_funding=1000000
    else:
        merch_funding=establish_json.get("merchant_deposit")

    out, contract_id = originate(cust_py, establish_params, cust_funding, merch_funding)
    
    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(contract_id)
    merch_ci = merch_py.contract(contract_id)

    # customer funds their side of the contract with the same amount as their initial balance
    out = add_cust_funding(cust_ci, cust_funding)

    # merchant funds their side of the contract with the same amount as their initial balance
    out = add_merch_funding(merch_ci, merch_funding)
    feetracker.add_result('addMerchFunding', out)

def test_reclaim(feetracker, cust_py, merch_py, cust_close_json, establish_params):
    '''
    Tests the 'reclaimFunding' entrypoint.
    'reclaimFunding' is to be used in a dual funded channel where only one party has deposited their funds and wishes to abort channel establishment.
    'expiry' is used by the merchant to force the customer to close the channel within the delay period.
    Entrypoints tested: 'addCustFunding', 'reclaimFunding'.
    '''
    print_header("Scenario test_reclaim: origination -> cust_funding -> reclaim_funding")

    # Create a dual-funded channel. If the establish_json is for a single funded channel, use the customer_deposit for the merchant so that it's non-zeo
    cust_funding=establish_json.get("customer_deposit")
    if establish_json.get("merchant_deposit") == 0:
        merch_funding=1000000
    else:
        merch_funding=establish_json.get("merchant_deposit")

    out, contract_id = originate(cust_py, establish_params, cust_funding, merch_funding)
    
    # Set contract interfaces for cust
    cust_ci = cust_py.contract(contract_id)

    # customer funds their side of the contract with the same amount as their initial balance
    out = add_cust_funding(cust_ci, cust_funding)

    # customer reclaims funding
    out = entrypoint_no_args(cust_ci, 'reclaimFunding')
    feetracker.add_result('reclaimFunding', out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", "-n", required=False, help="the address to connect to edo2net", default = "https://rpc.tzkt.io/edo2net/")
    parser.add_argument("--contract", "-z", required=True, help="zkchannels michelson contract")
    parser.add_argument("--cust", "-c", required=True, help="customer's testnet account json file")
    parser.add_argument("--merch", "-m", required=True, help="merchant's testnet account json file")
    parser.add_argument("--cust-close", "-cc", help="Filename (with path) to the <chanid>.close.json file created by zeekoe")
    parser.add_argument("--establish", "-e", required=True, help="Enter the filename (with path) to the establish.json file created by zeekoe")
    # parser.add_argument("--merch_close", "-mc", help="Enter the filename (with path) to the merch_expiry.json file created by zeekoe")
    args = parser.parse_args()

    if args.shell:
        pytezos = pytezos.using(shell=args.shell)
    print("Connecting to " + args.shell)

    cust_acc = args.cust
    merch_acc = args.merch
    establish_json_file = args.establish
    cust_close_json_file = args.cust_close
    # merch_close_file = args.merch_close

    # Set customer and merch pytezos interfaces
    cust_py = pytezos.using(key=cust_acc)
    cust_addr = read_json_file(cust_acc)['pkh']
    merch_py = pytezos.using(key=merch_acc)
    merch_addr = read_json_file(merch_acc)['pkh']

    establish_json = read_json_file(establish_json_file)
    cust_close_json = read_json_file(cust_close_json_file)
    # merch_close_json = read_json_file(merch_close_file)

    # load zchannel contracts
    main_code = ContractInterface.from_file(args.contract)

    # Activate cust and merch testnet accounts
    try:
        print("Activating cust account")
        cust_py.activate_account().fill().sign().send()
    except:
        print("Cust account already activated")

    try:
        print("Revealing cust pubkey")
        out = cust_py.reveal().autofill().sign().send()
    except:
        pass
    cust_pubkey = cust_py.key.public_key()

    try:
        print("Activating merch account")
        merch_py.activate_account().fill().sign().send()
    except: 
        print("Merch account already activated")

    try:
        print("Revealing merch pubkey")
        out = merch_py.reveal().autofill().sign().send()
    except:
        pass
    merch_pubkey = merch_py.key.public_key()

    feetracker = FeeTracker()
    test_custclaim(feetracker, cust_py, merch_py, cust_close_json, establish_json)
    test_dispute(feetracker, cust_py, merch_py, cust_close_json, establish_json)
    test_merchClaim(feetracker, cust_py, merch_py, cust_close_json, establish_json)
    test_dualfund(feetracker, cust_py, merch_py, cust_close_json, establish_json)
    test_reclaim(feetracker, cust_py, merch_py, cust_close_json, establish_json)
    feetracker.print_fees()

    print("Tests finished!")
