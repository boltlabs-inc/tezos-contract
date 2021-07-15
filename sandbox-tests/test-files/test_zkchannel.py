import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox
import sys, json

BAKE_ARGS = ['--minimal-timestamp']
CONTEXT_STRING = "zkChannels mutual close"

def form_initial_storage(cid, cust_addr, cust_pk, merch_addr, merch_pk, cust_funding_mt, merch_funding, rev_lock, self_delay, merch_ps_pk, close_flag):
    g2 = merch_ps_pk.get("g2")
    y2s = merch_ps_pk.get("y2s")
    x2 = merch_ps_pk.get("x2")
    custBal = 0
    merchBal = 0
    status = 0
    delayExpiry = 0

    return '(Pair (Pair (Pair (Pair {cid} {close_flag}) (Pair \"{context_string}\" (Pair \"{cust_addr}\" {custBal}))) (Pair (Pair {cust_funding_mt} (Pair \"{cust_pk}\" \"{delayExpiry}\")) (Pair {g2} (Pair \"{merch_addr}\" {merchBal})))) (Pair (Pair (Pair {merch_funding} \"{merch_pk}\") (Pair {merchPk0} (Pair {merchPk1} {merchPk2}))) (Pair (Pair {merchPk3} (Pair {merchPk4} {merchPk5})) (Pair {rev_lock} (Pair {self_delay} {status})))))'.format(
        cid=cid, 
        cust_addr=cust_addr, 
        cust_pk=cust_pk, 
        merch_addr=merch_addr, 
        merch_pk=merch_pk, 
        cust_funding_mt=cust_funding_mt, 
        merch_funding=merch_funding, 
        self_delay=self_delay, 
        rev_lock=rev_lock, 
        g2=g2, 
        merchPk0=y2s[0], 
        merchPk1=y2s[1], 
        merchPk2=y2s[2], 
        merchPk3=y2s[3], 
        merchPk4=y2s[4], 
        merchPk5=x2, 
        close_flag=close_flag, 
        context_string=CONTEXT_STRING, 
        custBal=custBal, 
        merchBal=merchBal, 
        status=status, 
        delayExpiry=delayExpiry)

def read_json_file(json_file):
    f = open(json_file)
    s = f.read()
    f.close()
    return json.loads(s)

def scenario_cust_close(contract_path, establish_json, cust_close_json):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1) # sleep after baking to prevent the error of blocks being produced in the future

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # We'll keep track of the total tezos fees/gas costs incurred by the customer
        entrypoint_cost = dict()
        cust_bal_start = sandbox.client(0).get_balance(cust_addr)

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_contract.tz"

        cust_funding_mt=establish_json.get("customer_deposit")
        merch_funding=establish_json.get("merchant_deposit")

        contract_name = "my_zkchannel"
        merch_ps_pk = establish_json.get("merchant_ps_public_key")
        close_scalar_bytes = establish_json.get("close_scalar_bytes")
        cid = establish_json.get("channel_id")

        rev_lock0 = "0x00"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(cid, cust_addr, cust_pk, merch_addr, merch_pk, cust_funding_mt, merch_funding, rev_lock0, self_delay, merch_ps_pk, close_scalar_bytes)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        old_bal = cust_bal_start
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["zkchannel"] = old_bal - current_bal

        # Add customer's funds
        sandbox.client(0).transfer(cust_funding_mt/1000000, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_funding, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        merch_old_bal = sandbox.client(0).get_balance(merch_addr)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["addFunding"] = old_bal - cust_funding_mt/1000000 - current_bal

        # Merchant initiates merch close
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'expiry',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        merch_current_bal = sandbox.client(0).get_balance(merch_addr)
        entrypoint_cost["expiry"]  = merch_old_bal - merch_current_bal

        # A final payment happens - Merchant signs off on chanID, balances,
        # revlock (and for now addresses, although that may change)
        new_cust_bal_mt = int(cust_close_json.get("customer_balance"))
        new_merch_bal_mt = int(cust_close_json.get("merchant_balance"))
        revocation_lock = cust_close_json.get("revocation_lock")

        cs = cust_close_json.get("closing_signature")
        sigma1, sigma2 = cs.get("sigma1"), cs.get("sigma2")

        storage = 'Pair (Pair {custBal} {merchBal}) {rev_lock_final} {s1} {s2}'.format(
            s1=sigma1, 
            s2=sigma2, 
            rev_lock_final=revocation_lock, 
            custBal=new_cust_bal_mt, 
            merchBal=new_merch_bal_mt)

        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each block takes two seconds, so with a self_delay of 3 seconds, the 
        # customer will be able to claim their balance after two blocks.
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["custClose"] = old_bal - current_bal

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClaim',
                                    '--burn-cap', burncap])
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["custClaim"] = old_bal - (current_bal - new_cust_bal_mt/1000000)


        print("Cost incurred when calling the following entrypoints (tez):")
        for k, v in entrypoint_cost.items():
            print(k + ": " + str(v))
        
        # Make sure every tez has been accounted for
        assert cust_bal_start == (
            current_bal
            + sum(entrypoint_cost.values()) - entrypoint_cost["expiry"]
            + cust_funding_mt/1000000
            - new_cust_bal_mt/1000000
            )
        return 

def scenario_mutual_close(contract_path, pubkey):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1) # sleep after baking to prevent the error of blocks being produced in the future

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # We'll keep track of the total tezos fees/gas costs incurred by the customer
        entrypoint_cost = dict()
        cust_bal_start = sandbox.client(0).get_balance(cust_addr)

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_contract.tz"

        cust_funding_mt=establish_json.get("customer_deposit")
        merch_funding=establish_json.get("merchant_deposit")

        contract_name = "my_zkchannel"
        merch_ps_pk = establish_json.get("merchant_ps_public_key")
        close_scalar_bytes = establish_json.get("close_scalar_bytes")
        cid = establish_json.get("channel_id")

        rev_lock0 = "0x00"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(cid, cust_addr, cust_pk, merch_addr, merch_pk, cust_funding_mt, merch_funding, rev_lock0, self_delay, merch_ps_pk, close_scalar_bytes)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        old_bal = cust_bal_start
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["zkchannel"] = old_bal - current_bal

        # Add customer's funds
        sandbox.client(0).transfer(cust_funding_mt/1000000, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_funding, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        merch_old_bal = sandbox.client(0).get_balance(merch_addr)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["addFunding"] = old_bal - cust_funding_mt/1000000 - current_bal

        # Create the mutual close state that customer and merchant settle on
        new_cust_bal = 3
        new_merch_bal = 2
        new_cust_bal_mt = int(new_cust_bal * 1000000)
        new_merch_bal_mt = int(new_merch_bal * 1000000)
        contract_addr = sandbox.client(0).get_contract_address(contract_name)
        
        mutual_state = '(Pair (Pair {cid} \"{context_string}\") (Pair \"{contract_addr}\" (Pair {new_cust_bal_mt} {new_merch_bal_mt} )))'.format(
            cid=cid, 
            context_string=CONTEXT_STRING, 
            contract_addr=contract_addr, 
            new_cust_bal_mt=new_cust_bal_mt, 
            new_merch_bal_mt=new_merch_bal_mt
        )

        # Merch signs off on mutual close state
        mutual_type = 'pair (pair bls12_381_fr string) (pair address (pair mutez mutez))'

        packed = sandbox.client(0).pack(mutual_state, mutual_type)
        merch_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap2")

        storage = '(Pair {cust_bal_mt} (Pair {merch_bal_mt} \"{merch_sig}\"))'.format(
            merch_sig=merch_sig, 
            cust_bal_mt=new_cust_bal_mt, 
            merch_bal_mt=new_merch_bal_mt)

        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'mutualClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["mutualClose"] = old_bal + new_cust_bal - current_bal

        # Make sure every tez has been accounted for
        assert cust_bal_start == (
            current_bal
            + sum(entrypoint_cost.values())
            + cust_funding_mt/1000000
            - new_cust_bal
            )

        print("Cost incurred when calling the following entrypoints (tez):")
        for k, v in entrypoint_cost.items():
            print(k + ": " + str(v))

        return 

if __name__ == "__main__":
    contract_path = sys.argv[1]
    establish_json_file = sys.argv[2]
    cust_close_json_file = sys.argv[3]
    if contract_path[:-1] != "/":
        contract_path += "/"
    print("Contract Path: ", contract_path)
    establish_json = read_json_file(establish_json_file)
    cust_close_json = read_json_file(cust_close_json_file)

    scenario_cust_close(contract_path, establish_json, cust_close_json)
    scenario_mutual_close(contract_path, establish_json)