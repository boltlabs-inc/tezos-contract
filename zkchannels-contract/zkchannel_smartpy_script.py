# This smart contract implements the zkchannel flow
import smartpy as sp

# build zeekoe source as follows:
# $ CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --features "allow_explicit_certificate_trust"
# generate sample inputs for scenario tests after successfully establishing the channel,
# make at least one payment and then proceed to close the channel as follows (in off chain mode):
# $ ./target/debug/zkchannel customer --config "./dev/Customer.toml" close --force my-zkchannel --off-chain
CID_FR = "0x5f0b6efabc46808589acc4ffcfa9e9c8412cc097e45d523463da557d2c675c67"
REV_LOCK_FR = "0x7723ecf912ca83f8c637e7341699dad476ba971506cbf5f6bdaaac313b761c2f"
SIGMA_1 = "0x1189f6f8bb0dc1c6d34abb4a00e9d990d1dd62a019bdbedf95c3d51b9b13bf5a38edb316f990c4142f5cc8ad6a14074a18c36110d08d3543d333f6f9c9fe42dc580774cce2f3d3d3e0eb498486cf2617477929e980faf9dc89be569b2b46e7cf"
SIGMA_2 = "0x101cae6b21d198c69532944c3fd06af167ccc256d3c27c4eca5ac501ce928d8c30467f549e8f4a8c82733943e06bd9290a12c39ddd1dc362b48e77a1fb629f3655a87b6a4d499183fc768717bf18666bb065825b8f06e72c40b68c8307a5e630"
PUB_GEN_G2 = "0x0b9ea946e3fa314fdf01e7f6077b383eb113cb0c6b9c45bdd76579ca6ffcd875828453fe119df06dd96222899e16b70e0597d482200131de43ed4185e8b816339acf1cf17432ef8c9b0ee6bee7ce7f4b90d0e223b463b7b036072ac350984a7d18a06ae675abb45a6fc99a015a6449407d514c13c237a69177a3c467198ffbad00c342fc747c5a02b7c1004aa40518910c0e5dcc467d1effb9f7a6a9b7c13034e1de1509f07be3084f6d83711c614dd8ea5cf875c37c58d8f1e69c1df3fb9fc6"
Y2S_0_G2 = "0x1249832415369e4a3043e21040b95583b7a868b9e73ff520884dd622b694defdfefe31ef0c11ec0956f2ac25b75f4ae00758ec3afe7d5160b2e9310954e5565e83b632d7075429dbd08ad795da021b2d175e49a6e4a402a387933fe5fd6c74b80c097ece2ae44bfe10347cf753165cfe80aea3823f7d140671afad20b620cc089f29f9c4095a8a9cf412290dfef1f8811399067199e2b871477921c38bd7ca53bbb8a89747c51f56ad35ce9f45c1a890417b77076673a683e23a98e23464598f"
Y2S_1_G2 = "0x0df5839732a5c6ecc2dac945897afbb775788042b6dade7181f29da2255a7c406f9e990ddf98f81f93c3caa5ec1fd1d40a43d9a34e76ce76b3ae48952ab83996025209ae2d5ad77dcb4b580390b4917fbefd5d9376d8de4ef872bfe5503327ac171a1cddbdfe6ab91794981172bab8c62dcac137c5a5824351d7f35d2b84f03c15ebe48d129ac0fb2dc34fbb230632fd0f8eb2bd39a6e8da0c5fb91aebb61ce522e460d7fd9995832c0f8be09ff44cb4df07d0aa9008207514442814018f61fb"
Y2S_2_G2 = "0x02048d8c4b04b83603d7078cda46549325aeb60b9b387a3b0bc8d84d49b5f210ca7dae080c7b5a3e2fb71c6938d5090710822f026a1367ba49f366f8b8605f9c008ed306a0a4b06c00816fb936299249871d77e91c89825e5d70b6e37c4d2e7f04b7abcb4aa2f095e8568b4d0ea9251e93f28bb6d98c058cd47194de7fb33a1c04e2bfe158c3e4dc34f1bf5f4125066b160d63ef314554cca42c22a3f5f57a9f54d8d8557a43661d322dc416985f3558c992b08c378e04a04e4f4043ebd25f38"
Y2S_3_G2 = "0x03f479529090932a017d95deee54d66048b1c99e286193734db8dc610bc85f62fcf761a61e289da376eddfc8eeb133721985f59205455baf92251ce5d922e27eff8391541d76b836e049041ea3eb394883348bad13053e8181e95be33c0c01500c6775a22a190985223d6ae7ebfdb0ac1ae87fc73d43a1a758086228d6c00f4a5679d497298544ac28ef4c012bba3b8b00f0d3e856f83a98a287e8eacfa516cc49608e99059f9960cc0ef1f9300938170df759157c8eb5f3cda6fd235d057a53"
Y2S_4_G2 = "0x1071998a1831f568d448c178b1c4d5f90a2c8191a027181957e87735eb7ec6c1b1b6f6245a2cff2d20e19a8b8719d91f05c265f2919fcc701c465462c423e05573442fb2b15eddd921bb77fa1ec29fc54ae24e672eb302ee695bd4726f629a4c0d42acb2a3f744a69cdd32733d6d467357a1d481088147cd086bfc33f391bb68c6a13c831d8deca8e36da604c63c08870c14be3600b29a3844ca2758a33172329ffa38284f99e96791fac534605c109cfe51752bcb8c143d6f86c2aa91a2a9aa"
X2_G2 = "0x1304a722c780f8b4973dd4da42ef4148af2a580aa3aeddbdaba604a86ec6e62750d699bd13647089278a1e6cc490986f181529059281216c836f054f392efb90b4890a57e46f43f7dc5a8faf0fe41a1b2cd54402dd0af86b78c3a8e175daf9530a2d9d970935dc3e93463565b431d38e13456092bce8da73ed1c2274a02dd29e1e3e0dda7a6f1e0f6c67ab741b4cc20212dcab1cad18c655264f6f56a9ad1a383be2cd0c72d2fdb59ffea76cb1c9d57f84a0d82ea391579bb5e11bc61e40d136"
MERCH_PS_PK_HASH = "0xb1082540d2d778a2ad3150f5fd88b8c34fd22a3e2035503e21f2d2fc0e43cf0f"
           
# A fixed scalar included in the message of Pointcheval Sanders closing signature when calling
# custClose.
CLOSE_SCALAR = "0x000000000000000000000000000000000000000000000000000000434c4f5345"
# context_string is contained in the tuple that gets signed when creating the mutual close 
# signature.
CONTEXT_STRING = "zkChannels mutual close"

# zkChannel contract statuses
# AWAITING_CUST_FUNDING - The contract has been originated but not funded by either party. In this 
# state, the customer must fund their portion of the channel using the addCustFunding entrypoint.
AWAITING_CUST_FUNDING = 0
# AWAITING_MERCH_FUNDING - The customer has funded their side of the contract and now the merchant 
# needs to fund their side using the addMerchFunding entrypoint. In this state, the customer can 
# still abort channel establishment by calling the reclaimFunding entrypoint to get back their 
# deposited funds. For channels funded by the customer alone, this state is skipped.
AWAITING_MERCH_FUNDING = 1
# OPEN - The contract is fully funded and the channel is open. From here the channel must be closed
# by calling one of the following entrypoints: expiry, custClose, mutualClose.
OPEN = 2
# EXPIRY - The merchant has initiated a unilateral channel closure by calling the expiry 
# entrypoint. delay_expiry is set to the time when the merchant will be able to claim the total 
# channel balance (using the merchClaim entrypoint) if the customer does not call custClose.
EXPIRY = 3
# CUST_CLOSE - The customer has called custClose (either from an OPEN or EXPIRY state). delay_expiry
# is set to the time when the customer will be able to claim their balance (using the custClaim 
# entrypoint). 
CUST_CLOSE = 4
# CLOSED - The channel balances have been paid out and no further activity can happen with the 
# channel. This status can be reached after custClaim, merchClaim, merchDispute, or mutualClose.
CLOSED = 5
# FUNDING_RECLAIMED - The customer aborted channel establishment after funding their side of the 
# channel. The customer's funds have been returned back to them and no further activity can happen
# with the channel. 
FUNDING_RECLAIMED = 6

 # This is the value of the identity element in the elliptic curve pairing group G1 from BLS12-381 
 # This is the uncompressed representation of the point at infinity of BLS12-381, ie it is 192 bytes long.
IDENTITY_IN_G1 = "0x400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
 

class ZkChannel(sp.Contract):

    @sp.global_lambda
    def convert_bytes_to_G2(val):
        x = sp.local('x', sp.unpack(sp.bytes("0x050a000000c0") + val, t = sp.TBls12_381_g2).open_some())
        sp.result(x.value)

    # Returns true if this element is the identity element (the point at infinity).
    @sp.global_lambda
    def is_g1_identity(val):
        # 'packed' denotes data that have been serialized with the pack function. Converting data 
        # to its serialized representation is a trick to make the equality check possible.
        packed_sigma1 = sp.pack(val)
        # sp.bls12_381_g1(BYTES) results in `PUSH bls12_381_g1 BYTES`.
        # This construction must stay valid in future Tezos protocols.
        packed_identity = sp.to_constant(sp.pack(sp.bls12_381_g1(IDENTITY_IN_G1)))
        sp.result(packed_sigma1 == packed_identity)

    # __init__ initializes the contract's storage at the time of origination. All the arguments 
    # must be provided in the origination operation. 
    def __init__(self, cid: sp.TBls12_381_fr, customer_address: sp.TAddress, merchant_address: sp.TAddress, merchant_public_key: sp.TKey, custFunding: sp.TMutez, merchFunding: sp.TMutez, self_delay: sp.TInt, close_scalar: sp.TBls12_381_fr, merch_ps_pk_hash: sp.TBytes):
        self.init(
            # the unique identifier for the channel.
            cid                 = cid,
            # customer tz1 address (derived from customer_public_key).
            customer_address    = customer_address,
            # merchant tz1 address (derived from merchant_public_key).
            merchant_address    = merchant_address,
            # merchant tezos public key
            merchant_public_key  = merchant_public_key,
            # customer's balance. The contract is initialized with this value set to the
            # customer's initial balance. The initial balance must be funded in one operation
            # using the addCustFunding entrypoint. If custClose is called, customer_balance 
            # stores the customer's closing balance.
            customer_balance     = custFunding,
            # merchant's balance. The contract is initialized with this value set to the merchant's 
            # initial balance. If the channel is funded by the customer alone, merchant_balance is 
            # set to 0 and addMerchFunding is not called. If it is a dual funded channel, the 
            # merchant's initial balance must be funded in one operation using the addMerchFunding 
            # entrypoint.
            merchant_balance     = merchFunding,
            # contract status. See  above for all the possible zkChannel contract statuses.
            status               = sp.nat(AWAITING_CUST_FUNDING),
            # revocation_lock initialized to 0x00. When the customer calls custClose, the revocation lock 
            # will be passed in as an argument and stored in revocation_lock. If the merchant has the 
            # revocation secret corresponding to revocation_lock, they can claim the entire balance using 
            # the merchDispute entrypoint.
            revocation_lock      = sp.bytes("0x00"),
            # An enforced delay period that must have elapsed between calling custClose and 
            # custClaim, and between calling expiry and merchClaim.
            self_delay           = self_delay,
            # if the delay is triggered, delay_expiry records when the delay is due to expire.
            delay_expiry         = sp.timestamp(0),
            # merch_ps_pk_hash is a sha3 hash over the merchant's Pointcheval Sanders public keys.
            merch_ps_pk_hash     = merch_ps_pk_hash)

    # addCustFunding is called by the customer to fund their portion of the channel (according to
    # the amount specified by custFunding). The full amount must be funded in one transaction. The
    # customer must fund their side of the channel before the merchant.
    @sp.entry_point
    def addCustFunding(self):
        # Only allow the customer to call the entrypoint.
        sp.verify(self.data.customer_address == sp.sender)        
        # Verify channel status == AWAITING_CUST_FUNDING.
        sp.verify(self.data.status == AWAITING_CUST_FUNDING)
        # Verify that the operation amount matches customer_balance. 
        sp.verify(sp.amount == self.data.customer_balance)        
        # If the channel is funded by the customer alone, set the channel status to OPEN. Else, set the channel 
        # status to AWAITING_MERCH_FUNDING.
        sp.if self.data.merchant_balance == sp.mutez(0):
            self.data.status = OPEN
        sp.else:
            self.data.status = AWAITING_MERCH_FUNDING

    # addMerchFunding is called by the merchant to fund their portion of the channel (according to
    # the amount specified by merchFunding). The full amount must be funded in one transaction. The
    # merchant must fund their side of the channel after the customer. This step is skipped 
    # for channels funded by the customer alone.
    @sp.entry_point
    def addMerchFunding(self):
        # Only allow the merchant to call the entrypoint.
        sp.verify(self.data.merchant_address == sp.sender)        
        # Verify channel status == AWAITING_MERCH_FUNDING.
        sp.verify(self.data.status == AWAITING_MERCH_FUNDING)
        # Verify that the operation amount matches merchFunding. 
        sp.verify(sp.amount == self.data.merchant_balance)
        # Set the channel status to OPEN.
        self.data.status = OPEN

    # reclaimFunding allows the customer to withdraw their funds
    # if the merchant has not funded their side of the channel yet.
    @sp.entry_point
    def reclaimFunding(self):
        # Only allow the customer to call the entrypoint.
        sp.verify(self.data.customer_address == sp.sender)
        # Verify that the channel status is AWAITING_MERCH_FUNDING. For the contract to have a 
        # status of AWAITING_MERCH_FUNDING, the following must be true:
        #     - it is a dual funded channel,
        #     - customer must have already funded their side of the channel, 
        #     - the merchant has not funded their side.
        sp.verify(self.data.status == AWAITING_MERCH_FUNDING)
        # Send the customer’s balance back to customer_address.
        sp.send(self.data.customer_address, self.data.customer_balance)
        # Set the channel status to FUNDING_RECLAIMED.
        self.data.status = FUNDING_RECLAIMED
 
    # expiry can be called by the merchant to initiate channel closure.
    # The customer should call custClose using the latest state. Otherwise,
    # after the delay expires, the merchant will be able to claim all the
    # funds in the channel using merchClaim.
    @sp.entry_point
    def expiry(self):
        # Only allow the merchant to call the entrypoint.
        sp.verify(self.data.merchant_address == sp.sender)
        # Verify that the contract status is OPEN.
        sp.verify(self.data.status == OPEN)
        # Record the time when the delay period will expire with self.data.delay_expiry.
        # The time is calculated by adding the number of seconds in self_delay to timestamp of
        # the block it is confirmed in.
        self.data.delay_expiry = sp.now.add_seconds(self.data.self_delay)
        # Set the channel status to EXPIRY.
        self.data.status = EXPIRY
 
    # merchClaim can only be called by the merchant after the expiry entrypoint has been called and # the delay period defined by self_delay has elapsed. If merchClaim is called, the total 
    # channel balance is disbursed to the merchant. The customer may call custClose during the 
    # delay period. If custClose is called before merchClaim, merchClaim can no longer be called.
    @sp.entry_point
    def merchClaim(self):
        # Only allow the merchant to call the entrypoint.
        sp.verify(self.data.merchant_address == sp.sender)
        # Verify that the contract status is EXPIRY.
        sp.verify(self.data.status == EXPIRY)
        # Verify that the delay period has passed.
        sp.verify(sp.now > self.data.delay_expiry)
        # Send the total balance to the merchant.
        sp.send(self.data.merchant_address, self.data.customer_balance + self.data.merchant_balance)
        # Set the channel status to CLOSED.
        self.data.status = CLOSED

    # custClose can be called by the customer to initiate a unilateral channel closure or update 
    # closing balances following an expiry entrypoint call. It can only be called by the customer 
    # while the channel status is OPEN or EXPIRY. The entrypoint validates the merchant's 
    # Pointcheval Sanders signature over a tuple containing the channel ID, close flag, rev lock, 
    # customer closing balance and merchant closing balance. The inputs to the entrypoint are the 
    # closing balances (customer_balance, merchant_balance), the revocation lock (revocation_lock), and the 
    # Pointcheval Sanders closing signature (sigma1, sigma2).
    @sp.entry_point
    def custClose(self, customer_balance: sp.TMutez, merchant_balance: sp.TMutez, revocation_lock: sp.TBytes, sigma1: sp.TBls12_381_g1, sigma2: sp.TBls12_381_g1, g2: sp.TBytes, y2s_0: sp.TBytes, y2s_1: sp.TBytes, y2s_2: sp.TBytes, y2s_3: sp.TBytes, y2s_4: sp.TBytes, x2: sp.TBytes):
        # Only allow the customer to call the entrypoint.
        sp.verify(self.data.customer_address == sp.sender)
        # Verify that the contract status is either OPEN or EXPIRY.
        sp.verify((self.data.status == OPEN) | (self.data.status == EXPIRY))

        merch_ps_pk_hash = sp.concat([y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2])
        sp.verify(sp.sha3(merch_ps_pk_hash) == self.data.merch_ps_pk_hash)

        ## Start of Pointcheval Sanders signature verification 
        # Fail if sigma1 is set to the identity element.
        sp.verify(self.is_g1_identity(sigma1)==False)
        # Prepare pairing check inputs
        _g2 = self.convert_bytes_to_G2(g2)
        _y2s_0 = self.convert_bytes_to_G2(y2s_0)
        _y2s_1 = self.convert_bytes_to_G2(y2s_1)
        _y2s_2 = self.convert_bytes_to_G2(y2s_2)
        _y2s_3 = self.convert_bytes_to_G2(y2s_3)
        _y2s_4 = self.convert_bytes_to_G2(y2s_4)
        _x2 = self.convert_bytes_to_G2(x2)
        cid = self.data.cid
        close_b = sp.bls12_381_fr(CLOSE_SCALAR)

        # Convert customer balance from mutez -> BLS12_381_fr (the scalar field of BLS12-381)
        # Mutez are encoded as 64-bit signed integers, so input must be smaller than the order of BLS12-381_fr
        # Use EDIV (Euclidean division) to convert mutez -> nat
        cust_b = sp.local('cust_b', sp.fst(sp.ediv(customer_balance, sp.mutez(1)).open_some()))
        # Use MUL to convert nat -> bls12_381_fr
        # Multiplies by the multiplicative identity of BLS12_381_fr using PUSH bls12_381_fr_1; MUL
        # Product is computed modulo the order of BLS12_381_fr
        cust_bal_b = sp.local("cust_bal_b", sp.mul(cust_b.value, sp.bls12_381_fr("0x01")))

        # Convert merchant balance from mutez -> BLS12_381_fr (the scalar field of BLS12-381)
        # Mutez are encoded as 64-bit signed integers, so input must be smaller than the order of BLS12-381_fr
        # Use EDIV (Euclidean division) to convert mutez -> nat
        merch_b = sp.local('merch_b', sp.fst(sp.ediv(merchant_balance, sp.mutez(1)).open_some()))
        # Use MUL to convert nat -> bls12_381_fr 
        # Multiplies by the multiplicative identity of BLS12_381_fr using PUSH bls12_381_fr_1; MUL
        # Product is computed modulo the order of BLS12_381_fr
        merch_bal_b = sp.local("merch_bal_b", sp.mul(merch_b.value, sp.bls12_381_fr("0x01")))

        # Convert revocation_lock from bytes -> fr
        # 0x050a000000 is the prefix for Fr elements in Michelson
        # 0x20 following this prefix means 32 bytes (0x20 in hexa) are expected next
        rev_lock_packed = sp.local('rev_lock_packed', sp.concat([sp.bytes("0x050a00000020"), revocation_lock]))
        rev_lock_b = sp.local('rev_lock_b', sp.unpack(rev_lock_packed.value, t = sp.TBls12_381_fr).open_some())

        # Verify Pointcheval Sanders signature against the message
        pk = [_y2s_0, _y2s_1, _y2s_2, _y2s_3, _y2s_4]
        # the message is composed of the channel ID, close flag, revocation lock, cust closing balance and 
        # merchant closing balance.
        msg = [cid, close_b, rev_lock_b.value, cust_bal_b.value, merch_bal_b.value]
        prod1 = sp.local('prod1', _x2)
        for i in range(0, len(msg)):
            prod1.value += sp.mul(pk[i], msg[i])
        # Compute the pairing check.
        sp.verify(sp.pairing_check([sp.pair(sigma1, prod1.value), sp.pair(sigma2, -_g2)]), message="pairing check failed")
        ## End of Pointcheval Sanders signature verification

        # Update the closing balances in the contract storage.  
        self.data.customer_balance = customer_balance
        self.data.revocation_lock = revocation_lock
        # Set delay_expiry to the current time plus the specified delay period, self_delay. When 
        # delay_expiry has passed, the customer will be able to claim their balance by calling 
        # custClaim. 
        self.data.delay_expiry = sp.now.add_seconds(self.data.self_delay)
        # Pay merchant immediately (unless amount is 0).
        sp.if merchant_balance != sp.tez(0):
            sp.send(self.data.merchant_address, merchant_balance)
        # Set the channel status to CUST_CLOSE.
        self.data.status = CUST_CLOSE
 
    # merchDispute can be called by the merchant if they have the revocation secret corresponding 
    # to the revocation lock in the customer's custClose entrypoint call. If the secret is valid, 
    # the merchant will receive the customer's balance.
    @sp.entry_point
    def merchDispute(self, revocation_secret):
        # Only allow the merchant to call the entrypoint.
        sp.verify(self.data.merchant_address == sp.sender)
        # Verify that the contract status is CUST_CLOSE.
        sp.verify(self.data.status == CUST_CLOSE)
        
        # Convert rev_lock in storage from LE to BE
        revocation_lock_be = sp.local('revocation_lock_be', sp.list([]))
        sp.for i in sp.range(0, 32):
            revocation_lock_be.value.push(sp.slice(self.data.revocation_lock, i, 1).open_some())
        # Verify the revocation secret hashes to the revocation lock
        sp.verify(sp.concat(revocation_lock_be.value) == sp.sha3(revocation_secret))
        # Send the customer's (revoked) balance to the merchant
        sp.send(self.data.merchant_address, self.data.customer_balance)
        # Set the channel status to CLOSED.
        self.data.status = CLOSED
 
    # custClaim can be called by the customer to claim their balance, but only
    # after the delay period from custClose has expired.
    @sp.entry_point
    def custClaim(self):
        # Only allow the customer to call the entrypoint.
        sp.verify(self.data.customer_address == sp.sender)
        # Verify that the contract status is CUST_CLOSE.
        sp.verify(self.data.status == CUST_CLOSE)
        # Verify that the delay period has passed.
        sp.verify(sp.now > self.data.delay_expiry)
        # Send the customer's balance to the customer.
        sp.send(self.data.customer_address, self.data.customer_balance)
        # Set the channel status to CLOSED.
        self.data.status = CLOSED
 
    # mutualClose can only be called by the customer and allows for an instant withdrawal
    # of the funds. mutualClose requires an EdDSA signature from the merchant over a tuple 
    # containing the contract-id, context-string, cid, customer_balance, and merchant_balance. The contract-id is
    # the KT1 address of the zkChannel contract. The context-string is defined in the contract 
    # storage. The contract-id and context-string are used to bind the signature to the type of 
    # channel closure and the contract.
    @sp.entry_point
    def mutualClose(self, customer_balance, merchant_balance, merchSig):
        # Only allow the customer to call the entrypoint.
        sp.verify(self.data.customer_address == sp.sender)
        # Verify that the contract status is OPEN.
        sp.verify(self.data.status == OPEN)
        # Check the merchant's EdDSA signature 
        sp.verify(sp.check_signature(self.data.merchant_public_key,
                                     merchSig,
                                     sp.pack(sp.record(
                                             contract_id = sp.self_address,
                                             context_string = sp.string(CONTEXT_STRING),
                                             cid = self.data.cid,
                                             customer_balance = customer_balance,
                                             merchant_balance = merchant_balance)
                                            )
                                    ))
        # Payout balances (unless amount is 0)
        # Note that all addresses must be implicit accounts (tz1), not smart contracts
        sp.if customer_balance != sp.tez(0):
            sp.send(self.data.customer_address, customer_balance)
        sp.if merchant_balance != sp.tez(0):
            sp.send(self.data.merchant_address, merchant_balance)
        # Set the channel status to CLOSED.
        self.data.status = CLOSED
 
 
 
@sp.add_test(name = "basic")
def test():
 
    scenario = sp.test_scenario()
    scenario.table_of_contents()
 
    scenario.h1("zkChannels")
    aliceCust = sp.test_account("Alice")
    bobMerch = sp.test_account("Bob")
 
    scenario.h2("Parties")
    scenario.p("We start with two accounts Alice (customer) and Bob (merchant):")
    scenario.show([aliceCust, bobMerch])
 
    # Set zkChannel parameters
    cid = sp.bls12_381_fr(CID_FR)
    close_scalar = sp.bls12_381_fr(CLOSE_SCALAR)
    # self_delay = 60*60*24 # seconds in one day - 86,400
    self_delay = 3 # seconds in one day - 86,400
    scenario.h2("On-chain installment")
    custFunding = sp.tez(5)
    merchFunding = sp.tez(0)
    g2 = sp.bytes(PUB_GEN_G2)
    y2s_0 = sp.bytes(Y2S_0_G2)
    y2s_1 = sp.bytes(Y2S_1_G2)
    y2s_2 = sp.bytes(Y2S_2_G2)
    y2s_3 = sp.bytes(Y2S_3_G2)
    y2s_4 = sp.bytes(Y2S_4_G2)
    x2 = sp.bytes(X2_G2)
    merch_ps_pk_hash = sp.bytes(MERCH_PS_PK_HASH)

    # add_compilation_target allows us to compile the contract using the smartpy-cli
    sp.add_compilation_target("compiled_contract", ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, close_scalar))

    # Correct closing balances for the sample signature
    customer_balance = sp.tez(4)
    merchant_balance = sp.tez(1)

    scenario.h2("Scenario 1: escrow -> expiry -> merchClaim")
    scenario.h3("escrow")
    mClaim = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += mClaim
    scenario.h3("Funding the channel")
    scenario += mClaim.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("expiry")
    scenario += mClaim.expiry().run(sender = bobMerch, now = sp.timestamp(0))
    scenario.h3("unsuccessful merchClaim before delay period")
    scenario += mClaim.merchClaim().run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    scenario.h3("successful merchClaim after delay period")
    scenario += mClaim.merchClaim().run(sender = bobMerch, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 2: escrow -> custClose -> custClaim")
    scenario.h3("escrow")
    cClaim = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += cClaim
    scenario.h3("Funding the channel")
    scenario += cClaim.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.p("Now the customer and merchant make a payment off chain.")
    scenario.p("For the payment to be considered complete, the customer should have received a signature from the merchant reflecting the final balances, and the merchant should have received the revocation_secret corresponding to the previous state's revocation_lock.")
    scenario.h3("custClose")
    scenario += cClaim.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, now = sp.timestamp(0))
    scenario.h3("unsuccessful custClaim attempt before delay period")
    scenario += cClaim.custClaim().run(sender = aliceCust, now = sp.timestamp(1), valid = False)
    scenario.h3("successful custClaim after delay period")
    scenario += cClaim.custClaim().run(sender = aliceCust, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 3: escrow -> custClose -> merchDispute")
    scenario.h3("escrow")
    mDisp = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += mDisp
    scenario.h3("Funding the channel")
    scenario += mDisp.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("custClose")
    scenario += mDisp.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust)
    scenario.h3("merchDispute called with incorrect revocation_secret")
    scenario += mDisp.merchDispute(sp.bytes("0x1111111111111111111111111111111111111111111111111111111111111111")).run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    # scenario.h3("merchDispute called with correct revocation_secret")
    # scenario += mDisp.merchDispute(sp.bytes(REV_SECRET)).run(sender = bobMerch, now = sp.timestamp(1))
 
    scenario.h2("Scenario 4: escrow -> expiry -> custClose")
    scenario.h3("escrow")
    cClose = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += cClose
    scenario.h3("Funding the channel")
    scenario += cClose.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("expiry")
    scenario += cClose.expiry().run(sender = bobMerch)
    scenario.h3("custClose")
    scenario += cClose.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust)
 
    scenario.h2("Scenario 5: escrow -> mutualClose")
    scenario.h3("escrow")
    mutClose = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += mutClose
    scenario.h3("Funding the channel")
    scenario += mutClose.addCustFunding().run(sender = aliceCust, amount = custFunding)
    # Merchant's signature on the latest state
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = mutClose.address,
                                                                  context_string = sp.string("zkChannels mutual close"),
                                                                  cid = cid,
                                                                  customer_balance = customer_balance,
                                                                  merchant_balance = merchant_balance)))
    scenario.h3("mutualClose")
    scenario += mutClose.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust)
 
    scenario.h2("Scenario 6: Failing tests for custClose")
    scenario.h3("escrow")
    failCust = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += failCust
    scenario += failCust.addCustFunding().run(sender = aliceCust, amount = custFunding)

    scenario.h3("Invalid revocation_lock (31 bytes instead of 32 bytes)")
    # short_revocation_lock has 31 bytes instead of 32 bytes
    short_revocation_lock = "0xef92f88aeed6781dc822fd6c88daf585474ab639aa06661df1fd05829b0ef7"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(short_revocation_lock),
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid revocation_lock (33 bytes instead of 32 bytes)")
    # long_revocation_lock has 33 bytes instead of 32 bytes
    long_revocation_lock = "0xef92f88aeed6781dc822fd6c88daf585474ab639aa06661df1fd05829b0ef7f7f7"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(long_revocation_lock), 
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid revocation_lock value")
    # invalid_revocation_lock has the correct length (32 bytes) but does not match the 
    # revocation_lock that the signature was produced over.
    invalid_revocation_lock = "0x1111111111111111111111111111111111111111111111111111111111111111"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(invalid_revocation_lock), 
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid cust balance")
    # set customer_balance to sp.tez(5) instead of sp.tez(4)
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = sp.tez(5), 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid merch balance")
    # set merchant_balance to sp.tez(0) instead of sp.tez(1)
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = sp.tez(0), 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature - identity element as sigma 1")
    # set sigma1 to the identity element (IDENTITY_IN_G1)
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(IDENTITY_IN_G1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - short sigma 1")
    # short_sigma_1 has a length of 95 bytes instead of 96 bytes
    short_sigma_1 = "0x1189f6f8bb0dc1c6d34abb4a00e9d990d1dd62a019bdbedf95c3d51b9b13bf5a38edb316f990c4142f5cc8ad6a14074a18c36110d08d3543d333f6f9c9fe42dc580774cce2f3d3d3e0eb498486cf2617477929e980faf9dc89be569b2b46e7"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(short_sigma_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - long sigma 1")
    # long_sigma_1 has a length of 97 bytes instead of 96 bytes
    long_sigma_1 = "0x1189f6f8bb0dc1c6d34abb4a00e9d990d1dd62a019bdbedf95c3d51b9b13bf5a38edb316f990c4142f5cc8ad6a14074a18c36110d08d3543d333f6f9c9fe42dc580774cce2f3d3d3e0eb498486cf2617477929e980faf9dc89be569b2b46e7cfaa"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(long_sigma_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - short sigma 2")
    # short_sigma_2 has a length of 95 bytes instead of 96 bytes
    short_sigma_2 = "0x101cae6b21d198c69532944c3fd06af167ccc256d3c27c4eca5ac501ce928d8c30467f549e8f4a8c82733943e06bd9290a12c39ddd1dc362b48e77a1fb629f3655a87b6a4d499183fc768717bf18666bb065825b8f06e72c40b68c8307a5e6"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(short_sigma_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - long sigma 2")
    # long_sigma_2 has a length of 97 bytes instead of 96 bytes
    long_sigma_2 = "0x101cae6b21d198c69532944c3fd06af167ccc256d3c27c4eca5ac501ce928d8c30467f549e8f4a8c82733943e06bd9290a12c39ddd1dc362b48e77a1fb629f3655a87b6a4d499183fc768717bf18666bb065825b8f06e72c40b68c8307a5e630aa"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(long_sigma_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature value - invalid sigma 1")
    invalid_sigma_1 = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(invalid_sigma_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature value - invalid sigma 2")
    invalid_sigma_2 = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    scenario += failCust.custClose(
        revocation_lock = sp.bytes(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(invalid_sigma_2),
        g2 = g2,
        y2s_0 = y2s_0,
        y2s_1 = y2s_1,
        y2s_2 = y2s_2,
        y2s_3 = y2s_3,
        y2s_4 = y2s_4,
        x2 = x2
        ).run(sender = aliceCust, valid = False)

    scenario.h2("Scenario 8: Failing tests for mutualClose")
    scenario.h3("escrow")
    failMut = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += failMut
    scenario += failMut.addCustFunding().run(sender = aliceCust, amount = custFunding)

    scenario.h3("Invalid signature - signing over incorrect contract_id")
    # Signing over failCust.address instead of failMut.address 
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = failCust.address,
                                                                  context_string = sp.string("zkChannels mutual close"),
                                                                  cid = cid,
                                                                  customer_balance = customer_balance,
                                                                  merchant_balance = merchant_balance)))
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect context string")
    # Signing over "incorrect context string" instead of "zkChannels mutual close"
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = failMut.address,
                                                                  context_string = sp.string("incorrect context string"),
                                                                  cid = cid,
                                                                  customer_balance = customer_balance,
                                                                  merchant_balance = merchant_balance)))
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect cid")
    # Signing over incorred cid (channel id)
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = failMut.address,
                                                                  context_string = sp.string("zkChannels mutual close"),
                                                                  cid = sp.bls12_381_fr("0x1111111111111111111111111111111111111111111111111111111111111111"),
                                                                  customer_balance = customer_balance,
                                                                  merchant_balance = merchant_balance)))
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect customer_balance")
    # Signing over customer_balance sp.tez(5) instead of sp.tez(4)
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = failMut.address,
                                                                  context_string = sp.string("incorrect context string"),
                                                                  cid = cid,
                                                                  customer_balance = sp.tez(5),
                                                                  merchant_balance = merchant_balance)))
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect merchant_balance")
    # Signing over merchant_balance sp.tez(0) instead of sp.tez(1)
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = failMut.address,
                                                                  context_string = sp.string("incorrect context string"),
                                                                  cid = cid,
                                                                  customer_balance = customer_balance,
                                                                  merchant_balance = sp.tez(0))))
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid input - incorrect customer_balance")
    # Create valid signature
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = failMut.address,
                                                                  context_string = sp.string("zkChannels mutual close"),
                                                                  cid = cid,
                                                                  customer_balance = customer_balance,
                                                                  merchant_balance = merchant_balance)))
    # Passing in customer_balance sp.tez(5) instead of sp.tez(4)
    scenario += failMut.mutualClose(customer_balance = sp.tez(5), merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid input - incorrect merchant_balance")
    # Passing in merchant_balance sp.tez(0) instead of sp.tez(1)
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = sp.tez(0), merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Verify signature used in above tests")
    scenario += failMut.mutualClose(customer_balance = customer_balance, merchant_balance = merchant_balance, merchSig = merchSig).run(sender = aliceCust, valid = True)

    scenario.h1("Dual funding tests")
    custFunding = sp.tez(3)
    merchFunding = sp.tez(2)
    scenario.h2("Scenario 8: escrow -> addCustFunding -> reclaimFunding -/-> addCustFunding")
    scenario.h3("escrow")
    reclaim = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += reclaim
    scenario.h3("Customer Funding their side of the channel")
    scenario += reclaim.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("Customer pulling out their side of the channel (before merchant funds their side)")
    scenario += reclaim.reclaimFunding().run(sender = aliceCust)
    scenario.h3("addCustFunding fails when being called for a second time")
    scenario += reclaim.addCustFunding().run(sender = aliceCust, amount = custFunding, valid=False)

    scenario.h2("Scenario 9: escrow -/-> addMerchFunding")
    scenario.h3("escrow")
    addMerch = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, close_scalar, merch_ps_pk_hash)
    scenario += addMerch
    scenario.h3("Merchant fails to fund their side of the channel before the customer")
    scenario += addMerch.addMerchFunding().run(sender = bobMerch, amount = merchFunding, valid=False)

    scenario.table_of_contents()
