# Example usage:
# python3 zkchannel_edo2net_broadcaster.py --contract=zkchannel_contract.tz --cust=tz1S6eSPZVQzHyPF2bRKhSKZhDZZSikB3e51.json --merch=tz1VcYZwxQoyxfjhpNiRkdCUe5rzs53LMev6.json --custclose=cust_close.json --merchclose=merch_close.json 

import argparse
from pprint import pprint
from pytezos import pytezos
from pytezos import Contract
from pytezos import ContractInterface
import json

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
        # pprint(result)
        fee = int(result['contents'][0]['fee'])
        storage_bytes = int(result['contents'][0]['storage_limit'])
        storage_cost = int(storage_bytes) * 250 # 250 mutez per storage_bytes byte on edo
        gas = int(result['contents'][0]['gas_limit'])
        total_cost = fee + storage_cost
        fee = {"total_cost":total_cost, "fee":fee, "storage_bytes":storage_bytes, "storage_cost":storage_cost, "gas":gas}
        self.fees.append({op_name:fee})

    def print_fees(self):
        pprint(self.fees)

def add_funding(ci, amt):
    print("Adding funds ({})".format(amt))
    out = ci.addFunding().with_amount(amt).inject(_async=False)
    print("addFunding ophash: ", out['hash'])
    return out

def originate(cust_py, cust_close_json, cust_funding, merch_funding):
    # Create initial storage for main zkchannel contract
    (pubkey, message, _) = get_cust_close_token(cust_close_json)
    chan_id_fr, _, _, _, close_flag = message

    g2 = pubkey.get("g2") 
    merchPk0 = pubkey.get("Y0") 
    merchPk1 = pubkey.get("Y1") 
    merchPk2 = pubkey.get("Y2") 
    merchPk3 = pubkey.get("Y3") 
    merchPk4 = pubkey.get("Y4") 
    merchPk5 = pubkey.get("X") 

    main_storage = {'cid': chan_id_fr, 
    'close_flag': close_flag,
    'context_string': "zkChannels mutual close",
    'custAddr': cust_addr, 
    'custBal':0, 
    'custFunding': cust_funding, 
    'custPk': cust_pubkey, 
    'delayExpiry': '1970-01-01T00:00:00Z', 
    'g2':g2,
    'merchAddr': merch_addr, 
    'merchBal': 0, 
    'merchFunding': merch_funding, 
    'merchPk': merch_pubkey, 
    'merchPk0': merchPk0,
    'merchPk1': merchPk1,
    'merchPk2': merchPk2,
    'merchPk3': merchPk3,
    'merchPk4': merchPk4,
    'merchPk5': merchPk5,
    'revLock': '0x00', 
    'selfDelay': 3, 
    'status': 0}

    # Originate main zkchannel contract
    print("Originate main zkChannel contract")
    out = cust_py.origination(script=main_code.script(initial_storage=main_storage)).autofill().sign().inject(_async=False)
    print("Originate zkChannel ophash: ", out['hash'])
    # Get address of main zkchannel contract
    opg = pytezos.shell.blocks[-20:].find_operation(out['hash'])
    main_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]
    print("zkChannel contract address: ", main_id)
    return out, main_id

def cust_close(ci, cust_close_json):
    # Form cust close storage
    (_, message, signature) = get_cust_close_token(cust_close_json)
    _, rev_lock_fr, _, _, _ = message
    s1, s2 = signature
    new_cust_bal_mt = cust_close_json["message"]["cust_bal"]
    new_merch_bal_mt = cust_close_json["message"]["merch_bal"]
    new_cust_bal = convert_mt_to_tez(new_cust_bal_mt)
    new_merch_bal = convert_mt_to_tez(new_merch_bal_mt)

    close_storage = {
        "custBal": new_cust_bal,
        "merchBal": new_merch_bal,
        "revLock": rev_lock_fr,
        "s1": s1,
        "s2": s2
    }

    print("Broadcasting Cust Close")
    out = ci.custClose(close_storage).inject(_async=False)
    print("Cust Close ophash: ", out['hash'])
    return out

def merch_dispute(ci, entrypoint, rev_secret):
    print('Broadcasting {}'.format(entrypoint))
    cmd = 'ci.{e}(\"{r}\").inject(_async=False)'.format(e=entrypoint, r=rev_secret)
    out = eval(cmd)
    print("{} ophash: ".format(entrypoint), out['hash'])
    return out

def entrypoint_no_args(ci, entrypoint):
    print('Broadcasting {}'.format(entrypoint))
    cmd = 'ci.{}().inject(_async=False)'.format(entrypoint)
    out = eval(cmd)
    print("{} ophash: ".format(entrypoint), out['hash'])
    return out

def scenario1(feetracker, cust_py, merch_py, cust_close_json):
    print("Scenario 1: origination -> dual funding -> expiry -> merch_claim")
    cust_funding=20000000
    merch_funding=10000000
    out, main_id = originate(cust_py, cust_close_json, cust_funding, merch_funding)
    feetracker.add_result('originate', out)

    # watchtower_command = "python3 passive_zkchannel_watchtower.py --contract {cid} --network {shell} --identity merchant".format(cid=main_id, shell=args.shell)
    # print("Run the watchtower with \n" + watchtower_command)
    # input("Press enter to continue")

    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(main_id)
    merch_ci = merch_py.contract(main_id)

    out = add_funding(cust_ci, cust_funding)
    feetracker.add_result('addFunding', out)

    out = entrypoint_no_args(cust_ci, 'reclaimFunding')
    feetracker.add_result('reclaimFunding', out)

    out = add_funding(cust_ci, cust_funding)
    out = add_funding(merch_ci, merch_funding)

    out = entrypoint_no_args(merch_ci, 'expiry')
    feetracker.add_result('expiry', out)

    out = entrypoint_no_args(merch_ci, 'merchClaim')
    feetracker.add_result('merchClaim', out)


def scenario2(feetracker, cust_py, merch_py, cust_close_json):
    print("Scenario 2: origination -> dual funding -> expiry -> cust_close -> merch_dispute")
    cust_funding=20000000
    merch_funding=10000000
    out, main_id = originate(cust_py, cust_close_json, cust_funding, merch_funding)

    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(main_id)
    merch_ci = merch_py.contract(main_id)

    out = add_funding(cust_ci, cust_funding)
    out = add_funding(merch_ci, merch_funding)
    out = entrypoint_no_args(merch_ci, 'expiry')
    out = cust_close(cust_ci, cust_close_json)
    feetracker.add_result('custClose', out)

    rev_secret = add_hex_prefix(merch_close_json['rev_secret'])
    out = merch_dispute(merch_ci, 'merchDispute', rev_secret)
    feetracker.add_result('merchDispute', out)


def scenario3(feetracker, cust_py, merch_py, cust_close_json):
    print("Scenario 3: origination -> single funding -> cust_close -> cust_claim")
    cust_funding=30000000
    merch_funding=0
    out, main_id = originate(cust_py, cust_close_json, cust_funding, merch_funding)

    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(main_id)
    merch_ci = merch_py.contract(main_id)

    out = add_funding(cust_ci, cust_funding)

    out = cust_close(cust_ci, cust_close_json)
    out = entrypoint_no_args(cust_ci, 'custClaim')
    feetracker.add_result('custClaim', out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", "-n", required=False, help="the address to connect to edo2net", default = "https://rpc.tzkt.io/edo2net/")
    parser.add_argument("--contract", "-z", required=True, help="zkchannels michelson contract")
    parser.add_argument("--cust", "-c", required=True, help="customer's testnet account json file")
    parser.add_argument("--merch", "-m", required=True, help="merchant's testnet account json file")
    parser.add_argument("--custclose", "-cc", required=True, help="Enter the filename (with path) to the cust_close.json file created by zkchannels-cli")
    parser.add_argument("--merchclose", "-mc", required=True, help="Enter the filename (with path) to the merch_close.json file created by zkchannels-cli")
    args = parser.parse_args()

    if args.shell:
        pytezos = pytezos.using(shell=args.shell)
    print("Connecting to edo2net via: " + args.shell)
    cust_acc = args.cust
    merch_acc = args.merch
    cust_close_file = args.custclose
    merch_close_file = args.merchclose

    # Set customer and merch pytezos interfaces
    cust_py = pytezos.using(key=cust_acc)
    cust_addr = read_json_file(cust_acc)['pkh']
    merch_py = pytezos.using(key=merch_acc)
    merch_addr = read_json_file(merch_acc)['pkh']

    cust_close_json = read_json_file(cust_close_file)
    merch_close_json = read_json_file(merch_close_file)

    # load zchannel contracts
    main_code = ContractInterface.from_file(args.contract)

    # Activate cust and merch testnet accounts
    try:
        print("Activating cust account")
        cust_py.activate_account().fill().sign().inject()
    except:
        print("Cust account already activated")

    try:
        print("Revealing cust pubkey")
        out = cust_py.reveal().autofill().sign().inject()
    except:
        pass
    cust_pubkey = cust_py.key.public_key()

    try:
        print("Activating merch account")
        merch_py.activate_account().fill().sign().inject()
    except: 
        print("Merch account already activated")

    try:
        print("Revealing merch pubkey")
        out = merch_py.reveal().autofill().sign().inject()
    except:
        pass
    merch_pubkey = merch_py.key.public_key()

    feetracker = FeeTracker()
    scenario1(feetracker, cust_py, merch_py, cust_close_json)
    scenario2(feetracker, cust_py, merch_py, cust_close_json)
    scenario3(feetracker, cust_py, merch_py, cust_close_json)
    feetracker.print_fees()

    print("Tests finished!")
