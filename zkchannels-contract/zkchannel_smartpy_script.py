# This smart contract implements the zkchannel flow
import smartpy as sp

# build zeekoe source as follows:
# $ CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --features "allow_explicit_certificate_trust"
# generate sample inputs for scenario tests after successfully establishing the channel,
# make at least one payment and then proceed to close the channel as follows (in off chain mode):
# $ ./target/debug/zkchannel customer --config "./dev/Customer.toml" close --force my-zkchannel --off-chain
CID_FR = "0xaa5f4b9d089e328bb1fcfe32300e45ec670331135dae73467a8813182534ae8b"
REV_LOCK_FR = "0x2fcdfd6ebb722754ee423603d11f8a380d06ffd991bcf2d64f1bb2de4c079d59"
SIGMA_1 = "0x10db5b493e43602f4083986369dbcd7974946d9244b74b30636b66a125ea08757fd04da5009dad70a894628b6b5bf69000fce48b1737a247d45908f7464a962ed9632e16b92ea4dfb8b045b9e019e4c61cfd12b1be33f5f0dc5f98856ec7b515"
SIGMA_2 = "0x10b3d5f631c6fd8fed3f507a1907317de5d644c767c7e2e4d632402d3e3fabf2fea69fe35179d83ca8ce205224e5c7210201c0cfd1d3612aecfda8456c08f92121c0523b4670228de1b8fd11c7755e3644f7dc4a85e8dfaec808e0b7f53c465d"
PUB_GEN_G2 = "0x1811b6c1b69de4f148bc1dd8f2b5066c79e85ef63af97711ba2d1b4cda9137a6ba58749c1fd28c8c9b4d08fdad949216117abce68370a1b86f7f6b77ffdd52cd96f3382d79f7cd43c25bb45f9d69781b2624d292c5318f0c3609b6c41ad57ea8040d188d060274b3bc7d9ed6f6addb159faca876a70c4c5d60ddb85abac084e4463848f14449b92f582211401dbec1830bc18ebecbf074b63736685ce39d238839710eae4705fe0633e98c36f9cfad515018aa6cf4838938921632255a43e95c"
Y2S_0_G2 = "0x1786214a13b25ea5c597e9dc744e65012a98f48241e6d03406bd63789acfa7b88b383f5863d3ccf77e12cba598f85c2913e043aec93a41700ad9743e2fe3720cf14f1f9439bfcb0107c4d003af8fe197d91e3da6632b11e490b2e6dff334906f148e61ff4d818c44cf59b0dadb9a6fad18419a06e03c1c549dc9a8ad8874401661d1505f7b92cb3f659f3f22f60d12a506c58b494c0269f7b2d52e543cfa6cbf791c9e4913a04bd0889e94fbbc1b6758b48ea95bd3cc73734b46717bb09a78ed"
Y2S_1_G2 = "0x123670d7d9ac450b092f09f0d6041b1b11340c2c0ddd1df6f2848a6fb3805966bab35dbe8027774afb34d8445cad05a1061c74b48c425d8c286772f35d1d0842aea727f9c8c6e89d6db7408039ae7cb607ec6252fdc97c202101e8314b4c25f103dcfcaedd2eb1b2cdeb467833b90256f075b65dd72215e1c122032768e8610d62868da74573ede8962c46488ca54ce0157ebdbffc3f3ca748cfd642355b5edef44430586ed87f61bde6579a2fab2df5769610314081ac8bb4f9f332d85b211c"
Y2S_2_G2 = "0x157f98b360c2c36649b06a40968683257575c72375dcbdb7a9616fe57369d7cca37041083284c09acf6f749bc45970480357046ba3f721a48506af254edb01dcd6d756b59a5dd2101777203b77f87721c3701eca64d4e171fa5c6c31cc99103907a7503659719e10a95ba124dc562ae4d8a4e12c786bf2f8f6902b0427540249357b3c5c65343e4dbb82683892d6be0718f7ad957036cf1fb909ed670fd2abac55f18aa70b1cd2efcf5b3e8e59c26432dc2036566cc305c4a33a39bb0dcc8e69"
Y2S_3_G2 = "0x17b5ccfa3c58f1a1f99c52ad71f97ffb7cf1bb1e89e7ee9b4d57b3681f38bbb782e17e282aee537a1868162259083ee811f172ed897d67e5e50dee85db8d5ba21244068199d4542e423a895c7483cd9663a85f62bf9883bf1759b7d6034f1c1819dff3aa1a78b551455a277051d705ad8dab10da4f4f6d182eb4841dde1e86c655772aa24b831db1e1769ff454040935016117eb5606ccb068ab70b854a802f9302731c1bca4a23edc1c608004eda465202519f3d1578de67716e6b5dec7b1f5"
Y2S_4_G2 = "0x11bace6a644a879ef7a1ed0445028ea915a4644c85d14876114800d0e3db25e8008b1cd49622ca2b5d9b85754677f1250854f0fb98b7904703660131a62b46eea8baf079d15e2ee2f11d5172c5145b482c0d1b88cd6d59b8f117bd0be63b242c162eda5c99321eecb567951dbbe38880e478152e3f83f25d4d4c49fbe5789e717aded01312f3d6173dee48a03a62c7a0106c3e6d4cf4043e3033a44d923dec84001e82a0d6c47edc6c179078b9d9afff31ca60db0cf0ff29457913a093f659a4"
X2_G2 = "0x06d5fc42249bcdb0b34b3ff14f225da782b98bb2d8e425ada8f98e49362534391d3b945594130e679425088df5b35f4c16a961f05445a3a222db91f988267851c13bff25519a9e3bee0f2e7affac0eaf04c3c0cb0490ddf4bd99412af2d227db038e5e5b64d9d11b6eb9cd969913353ded1f06dcf549bee6ab280673b598dd8fd673f3afec8ccf6a00994dc0e911fbff09e862287b9ffa330953421ab76453fffcbe5d100de99929f863631adcc985bba2c6cd8854598c5e997c98aaa93cb547"
CLOSE_SCALAR = "0x000000000000000000000000000000000000000000000000000000434c4f5345"
CONTEXT_STRING = "zkChannels mutual close"
REV_SECRET = "0x089bd7223e599b9e9c9ec878a19144d44832db1c93ebf80f763365f9fec8ab0d"

CUST_DEPOSIT_MUTEZ = 1000
MERCH_DEPOSIT_MUTEZ = 0
CUST_CLOSE_BALANCE_MUTEZ = 950
MERCH_CLOSE_BALANCE_MUTEZ = 50

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
    def __init__(self, cid: sp.TBls12_381_fr, customer_address: sp.TAddress, merchant_address: sp.TAddress, merchant_public_key: sp.TKey, custFunding: sp.TMutez, merchFunding: sp.TMutez, self_delay: sp.TInt, g2: sp.TBls12_381_g2, y2s_0: sp.TBls12_381_g2, y2s_1: sp.TBls12_381_g2, y2s_2: sp.TBls12_381_g2, y2s_3: sp.TBls12_381_g2, y2s_4: sp.TBls12_381_g2, x2: sp.TBls12_381_g2, revocation_lock: sp.TBls12_381_fr, status: sp.TNat, delay_expiry: sp.TTimestamp):
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
            status               = status,
            # revocation_lock initialized to 0x00. When the customer calls custClose, the revocation lock 
            # will be passed in as an argument and stored in revocation_lock. If the merchant has the 
            # revocation secret corresponding to revocation_lock, they can claim the entire balance using 
            # the merchDispute entrypoint.
            revocation_lock      = revocation_lock,
            # An enforced delay period that must have elapsed between calling custClose and 
            # custClaim, and between calling expiry and merchClaim.
            self_delay           = self_delay,
            # if the delay is triggered, delay_expiry records when the delay is due to expire.
            delay_expiry         = delay_expiry,
            g2                   = g2,                # Pointcheval Sanders pubkey
            y2s_0                = y2s_0,             # Pointcheval Sanders pubkey
            y2s_1                = y2s_1,             # Pointcheval Sanders pubkey
            y2s_2                = y2s_2,             # Pointcheval Sanders pubkey
            y2s_3                = y2s_3,             # Pointcheval Sanders pubkey
            y2s_4                = y2s_4,             # Pointcheval Sanders pubkey
            x2                   = x2                 # Pointcheval Sanders pubkey
        )
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
    def custClose(self, customer_balance: sp.TMutez, merchant_balance: sp.TMutez, revocation_lock: sp.TBls12_381_fr, sigma1: sp.TBls12_381_g1, sigma2: sp.TBls12_381_g1):
        # Only allow the customer to call the entrypoint.
        sp.verify(self.data.customer_address == sp.sender)
        # Verify that the contract status is either OPEN or EXPIRY.
        sp.verify((self.data.status == OPEN) | (self.data.status == EXPIRY))

        ## Start of Pointcheval Sanders signature verification 
        # Fail if sigma1 is set to the identity element.
        sp.verify(self.is_g1_identity(sigma1)==False)
        # Prepare pairing check inputs
        g2 = self.data.g2
        y2s0 = self.data.y2s_0
        y2s1 = self.data.y2s_1
        y2s2 = self.data.y2s_2
        y2s3 = self.data.y2s_3
        y2s4 = self.data.y2s_4
        x2 = self.data.x2
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

        # Verify Pointcheval Sanders signature against the message
        pk = [y2s0, y2s1, y2s2, y2s3, y2s4]
        # the message is composed of the channel ID, close flag, revocation lock, cust closing balance and 
        # merchant closing balance.
        msg = [cid, close_b, revocation_lock, cust_bal_b.value, merch_bal_b.value]
        prod1 = sp.local('prod1', x2)
        for i in range(0, len(msg)):
            prod1.value += sp.mul(pk[i], msg[i])
        # Compute the pairing check.
        sp.verify(sp.pairing_check([sp.pair(sigma1, prod1.value), sp.pair(sigma2, -g2)]), message="pairing check failed")
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
        # Compute hash of the secret (in bytes), then convert to bls12_381_fr
        hash_bytes = sp.sha3(revocation_secret)
        hash_packed = sp.local('hash_packed', sp.concat([sp.bytes("0x050a00000020"), hash_bytes]))
        hash_fr = sp.local('hash_fr', sp.unpack(hash_packed.value, t = sp.TBls12_381_fr).open_some())
        # Verify the revocation secret hashes to the revocation lock
        sp.verify_equal(self.data.revocation_lock, hash_fr.value)
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
    init_revocation_lock = sp.bls12_381_fr("0x00")
    init_delay_expiry = sp.timestamp(0)
    init_status = sp.nat(AWAITING_CUST_FUNDING)
    # self_delay = 60*60*24 # seconds in one day - 86,400
    self_delay = 3 # seconds in one day - 86,400
    scenario.h2("On-chain installment")
    custFunding = sp.mutez(CUST_DEPOSIT_MUTEZ)
    merchFunding = sp.mutez(MERCH_DEPOSIT_MUTEZ)
    g2 = sp.bls12_381_g2(PUB_GEN_G2)
    y2s_0 = sp.bls12_381_g2(Y2S_0_G2)
    y2s_1 = sp.bls12_381_g2(Y2S_1_G2)
    y2s_2 = sp.bls12_381_g2(Y2S_2_G2)
    y2s_3 = sp.bls12_381_g2(Y2S_3_G2)
    y2s_4 = sp.bls12_381_g2(Y2S_4_G2)
    x2 = sp.bls12_381_g2(X2_G2)

    # Correct closing balances for the sample signature
    customer_balance = sp.mutez(CUST_CLOSE_BALANCE_MUTEZ)
    merchant_balance = sp.mutez(MERCH_CLOSE_BALANCE_MUTEZ)

    # add_compilation_target allows us to compile the contract using the smartpy-cli
    sp.add_compilation_target("compiled_contract", ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry))

    scenario.h2("Scenario 1: escrow -> expiry -> merchClaim")
    scenario.h3("escrow")
    mClaim = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
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
    cClaim = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
    scenario += cClaim
    scenario.h3("Funding the channel")
    scenario += cClaim.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.p("Now the customer and merchant make a payment off chain.")
    scenario.p("For the payment to be considered complete, the customer should have received a signature from the merchant reflecting the final balances, and the merchant should have received the revocation_secret corresponding to the previous state's revocation_lock.")
    scenario.h3("custClose")
    scenario += cClaim.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance,
        merchant_balance = merchant_balance,
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, now = sp.timestamp(0))
    scenario.h3("unsuccessful custClaim attempt before delay period")
    scenario += cClaim.custClaim().run(sender = aliceCust, now = sp.timestamp(1), valid = False)
    scenario.h3("successful custClaim after delay period")
    scenario += cClaim.custClaim().run(sender = aliceCust, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 3: escrow -> custClose -> merchDispute")
    scenario.h3("escrow")
    mDisp = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
    scenario += mDisp
    scenario.h3("Funding the channel")
    scenario += mDisp.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("custClose")
    scenario += mDisp.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust)
    scenario.h3("merchDispute called with incorrect revocation_secret")
    scenario += mDisp.merchDispute(sp.bytes("0x1111111111111111111111111111111111111111111111111111111111111111")).run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    scenario.h3("merchDispute called with correct revocation_secret")
    scenario += mDisp.merchDispute(sp.bytes(REV_SECRET)).run(sender = bobMerch, now = sp.timestamp(1))
 
    scenario.h2("Scenario 4: escrow -> expiry -> custClose")
    scenario.h3("escrow")
    cClose = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
    scenario += cClose
    scenario.h3("Funding the channel")
    scenario += cClose.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("expiry")
    scenario += cClose.expiry().run(sender = bobMerch)
    scenario.h3("custClose")
    scenario += cClose.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust)
 
    scenario.h2("Scenario 5: escrow -> mutualClose")
    scenario.h3("escrow")
    mutClose = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
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
    failCust = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
    scenario += failCust
    scenario += failCust.addCustFunding().run(sender = aliceCust, amount = custFunding)

    scenario.h3("Invalid revocation_lock (31 bytes instead of 32 bytes)")
    # short_revocation_lock has 31 bytes instead of 32 bytes
    short_revocation_lock = "0xef92f88aeed6781dc822fd6c88daf585474ab639aa06661df1fd05829b0ef7"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(short_revocation_lock), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid revocation_lock (33 bytes instead of 32 bytes)")
    # long_revocation_lock has 33 bytes instead of 32 bytes
    long_revocation_lock = "0xef92f88aeed6781dc822fd6c88daf585474ab639aa06661df1fd05829b0ef7f7f7"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(long_revocation_lock), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid revocation_lock value")
    # invalid_revocation_lock has the correct length (32 bytes) but does not match the 
    # revocation_lock that the signature was produced over.
    invalid_revocation_lock = "0x1111111111111111111111111111111111111111111111111111111111111111"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(invalid_revocation_lock), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid cust balance")
    # set customer_balance to sp.tez(5) instead of sp.tez(4)
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = sp.tez(5), 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid merch balance")
    # set merchant_balance to sp.tez(0) instead of sp.tez(1)
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = sp.tez(0), 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature - identity element as sigma 1")
    # set sigma1 to the identity element (IDENTITY_IN_G1)
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(IDENTITY_IN_G1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - short sigma 1")
    # short_sigma_1 has a length of 95 bytes instead of 96 bytes
    short_sigma_1 = "0x1189f6f8bb0dc1c6d34abb4a00e9d990d1dd62a019bdbedf95c3d51b9b13bf5a38edb316f990c4142f5cc8ad6a14074a18c36110d08d3543d333f6f9c9fe42dc580774cce2f3d3d3e0eb498486cf2617477929e980faf9dc89be569b2b46e7"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(short_sigma_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - long sigma 1")
    # long_sigma_1 has a length of 97 bytes instead of 96 bytes
    long_sigma_1 = "0x1189f6f8bb0dc1c6d34abb4a00e9d990d1dd62a019bdbedf95c3d51b9b13bf5a38edb316f990c4142f5cc8ad6a14074a18c36110d08d3543d333f6f9c9fe42dc580774cce2f3d3d3e0eb498486cf2617477929e980faf9dc89be569b2b46e7cfaa"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(long_sigma_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - short sigma 2")
    # short_sigma_2 has a length of 95 bytes instead of 96 bytes
    short_sigma_2 = "0x101cae6b21d198c69532944c3fd06af167ccc256d3c27c4eca5ac501ce928d8c30467f549e8f4a8c82733943e06bd9290a12c39ddd1dc362b48e77a1fb629f3655a87b6a4d499183fc768717bf18666bb065825b8f06e72c40b68c8307a5e6"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(short_sigma_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length - long sigma 2")
    # long_sigma_2 has a length of 97 bytes instead of 96 bytes
    long_sigma_2 = "0x101cae6b21d198c69532944c3fd06af167ccc256d3c27c4eca5ac501ce928d8c30467f549e8f4a8c82733943e06bd9290a12c39ddd1dc362b48e77a1fb629f3655a87b6a4d499183fc768717bf18666bb065825b8f06e72c40b68c8307a5e630aa"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(long_sigma_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature value - invalid sigma 1")
    invalid_sigma_1 = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(invalid_sigma_1), 
        sigma2 = sp.bls12_381_g1(SIGMA_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature value - invalid sigma 2")
    invalid_sigma_2 = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    scenario += failCust.custClose(
        revocation_lock = sp.bls12_381_fr(REV_LOCK_FR), 
        customer_balance = customer_balance, 
        merchant_balance = merchant_balance, 
        sigma1 = sp.bls12_381_g1(SIGMA_1), 
        sigma2 = sp.bls12_381_g1(invalid_sigma_2)
        ).run(sender = aliceCust, valid = False)

    scenario.h2("Scenario 8: Failing tests for mutualClose")
    scenario.h3("escrow")
    failMut = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
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
    reclaim = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
    scenario += reclaim
    scenario.h3("Customer Funding their side of the channel")
    scenario += reclaim.addCustFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("Customer pulling out their side of the channel (before merchant funds their side)")
    scenario += reclaim.reclaimFunding().run(sender = aliceCust)
    scenario.h3("addCustFunding fails when being called for a second time")
    scenario += reclaim.addCustFunding().run(sender = aliceCust, amount = custFunding, valid=False)

    scenario.h2("Scenario 9: escrow -/-> addMerchFunding")
    scenario.h3("escrow")
    addMerch = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, self_delay, g2, y2s_0, y2s_1, y2s_2, y2s_3, y2s_4, x2, init_revocation_lock, init_status, init_delay_expiry)
    scenario += addMerch
    scenario.h3("Merchant fails to fund their side of the channel before the customer")
    scenario += addMerch.addMerchFunding().run(sender = bobMerch, amount = merchFunding, valid=False)

    scenario.table_of_contents()