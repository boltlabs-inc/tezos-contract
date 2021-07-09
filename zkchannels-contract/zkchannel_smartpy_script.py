# This smart contract implements the zkchannel flow
import smartpy as sp
 
# sample inputs for scenario tests
CID_FR = "0x5f0b6efabc46808589acc4ffcfa9e9c8412cc097e45d523463da557d2c675c67"
REV_LOCK_FR = "0x7723ecf912ca83f8c637e7341699dad476ba971506cbf5f6bdaaac313b761c2f"
SIG_S1_G1 = "0x1189f6f8bb0dc1c6d34abb4a00e9d990d1dd62a019bdbedf95c3d51b9b13bf5a38edb316f990c4142f5cc8ad6a14074a18c36110d08d3543d333f6f9c9fe42dc580774cce2f3d3d3e0eb498486cf2617477929e980faf9dc89be569b2b46e7cf"
SIG_S2_G1 = "0x101cae6b21d198c69532944c3fd06af167ccc256d3c27c4eca5ac501ce928d8c30467f549e8f4a8c82733943e06bd9290a12c39ddd1dc362b48e77a1fb629f3655a87b6a4d499183fc768717bf18666bb065825b8f06e72c40b68c8307a5e630"
PUB_GEN_G2 = "0x0b9ea946e3fa314fdf01e7f6077b383eb113cb0c6b9c45bdd76579ca6ffcd875828453fe119df06dd96222899e16b70e0597d482200131de43ed4185e8b816339acf1cf17432ef8c9b0ee6bee7ce7f4b90d0e223b463b7b036072ac350984a7d18a06ae675abb45a6fc99a015a6449407d514c13c237a69177a3c467198ffbad00c342fc747c5a02b7c1004aa40518910c0e5dcc467d1effb9f7a6a9b7c13034e1de1509f07be3084f6d83711c614dd8ea5cf875c37c58d8f1e69c1df3fb9fc6"
MERCH_PK0_G2 = "0x1249832415369e4a3043e21040b95583b7a868b9e73ff520884dd622b694defdfefe31ef0c11ec0956f2ac25b75f4ae00758ec3afe7d5160b2e9310954e5565e83b632d7075429dbd08ad795da021b2d175e49a6e4a402a387933fe5fd6c74b80c097ece2ae44bfe10347cf753165cfe80aea3823f7d140671afad20b620cc089f29f9c4095a8a9cf412290dfef1f8811399067199e2b871477921c38bd7ca53bbb8a89747c51f56ad35ce9f45c1a890417b77076673a683e23a98e23464598f"
MERCH_PK1_G2 = "0x0df5839732a5c6ecc2dac945897afbb775788042b6dade7181f29da2255a7c406f9e990ddf98f81f93c3caa5ec1fd1d40a43d9a34e76ce76b3ae48952ab83996025209ae2d5ad77dcb4b580390b4917fbefd5d9376d8de4ef872bfe5503327ac171a1cddbdfe6ab91794981172bab8c62dcac137c5a5824351d7f35d2b84f03c15ebe48d129ac0fb2dc34fbb230632fd0f8eb2bd39a6e8da0c5fb91aebb61ce522e460d7fd9995832c0f8be09ff44cb4df07d0aa9008207514442814018f61fb"
MERCH_PK2_G2 = "0x02048d8c4b04b83603d7078cda46549325aeb60b9b387a3b0bc8d84d49b5f210ca7dae080c7b5a3e2fb71c6938d5090710822f026a1367ba49f366f8b8605f9c008ed306a0a4b06c00816fb936299249871d77e91c89825e5d70b6e37c4d2e7f04b7abcb4aa2f095e8568b4d0ea9251e93f28bb6d98c058cd47194de7fb33a1c04e2bfe158c3e4dc34f1bf5f4125066b160d63ef314554cca42c22a3f5f57a9f54d8d8557a43661d322dc416985f3558c992b08c378e04a04e4f4043ebd25f38"
MERCH_PK3_G2 = "0x03f479529090932a017d95deee54d66048b1c99e286193734db8dc610bc85f62fcf761a61e289da376eddfc8eeb133721985f59205455baf92251ce5d922e27eff8391541d76b836e049041ea3eb394883348bad13053e8181e95be33c0c01500c6775a22a190985223d6ae7ebfdb0ac1ae87fc73d43a1a758086228d6c00f4a5679d497298544ac28ef4c012bba3b8b00f0d3e856f83a98a287e8eacfa516cc49608e99059f9960cc0ef1f9300938170df759157c8eb5f3cda6fd235d057a53"
MERCH_PK4_G2 = "0x1071998a1831f568d448c178b1c4d5f90a2c8191a027181957e87735eb7ec6c1b1b6f6245a2cff2d20e19a8b8719d91f05c265f2919fcc701c465462c423e05573442fb2b15eddd921bb77fa1ec29fc54ae24e672eb302ee695bd4726f629a4c0d42acb2a3f744a69cdd32733d6d467357a1d481088147cd086bfc33f391bb68c6a13c831d8deca8e36da604c63c08870c14be3600b29a3844ca2758a33172329ffa38284f99e96791fac534605c109cfe51752bcb8c143d6f86c2aa91a2a9aa"
MERCH_PK5_G2 = "0x1304a722c780f8b4973dd4da42ef4148af2a580aa3aeddbdaba604a86ec6e62750d699bd13647089278a1e6cc490986f181529059281216c836f054f392efb90b4890a57e46f43f7dc5a8faf0fe41a1b2cd54402dd0af86b78c3a8e175daf9530a2d9d970935dc3e93463565b431d38e13456092bce8da73ed1c2274a02dd29e1e3e0dda7a6f1e0f6c67ab741b4cc20212dcab1cad18c655264f6f56a9ad1a383be2cd0c72d2fdb59ffea76cb1c9d57f84a0d82ea391579bb5e11bc61e40d136"
CLOSE_FLAG_B = "0x000000000000000000000000000000000000000000000000000000434c4f5345"

MERCH_PS_PK_HASH = "0x8175037f751865cbbe7c553515283a46c8355e2ba302106320faf591b51af0b0" 

AWAITING_FUNDING = 0
OPEN = 1
EXPIRY = 2
CUST_CLOSE = 3
CLOSED = 4
 
ZERO_IN_G1 = "0x400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
 
CONTEXT_STRING = "zkChannels mutual close"

# cid is a unique identifier for the channel.
# Addresses are used both for interacting with contract, and receiving payouts. Addresses must be for implicit accounts (tz1) only, not smart contracts.
# Public keys are used for verifying signatures required for certain state transitions.
# revLock is the revocation lock used to punish a customer who broadcasts a revoked custState.
# selfDelay defines the delay (in seconds) during which the other party can counter specific state transitions.
# delayExpiry is the unix timestamp corresponding to when the delay expires.
class ZkChannel(sp.Contract):

    @sp.global_lambda
    def is_g1_not_zero(val):
        packed_s1 = sp.pack(val)
        packed_zero = sp.to_constant(sp.pack(sp.bls12_381_g1(ZERO_IN_G1)))
        sp.result(packed_s1 != packed_zero)

    @sp.global_lambda
    def convert_bytes_to_G2(val):
        x = sp.local('x', sp.unpack(sp.bytes("0x050a000000c0") + val, t = sp.TBls12_381_g2).open_some())
        sp.result(x.value)

    def __init__(self, cid, custAddr, merchAddr, merchPk, custFunding, merchFunding, selfDelay, merchPsPkHash):
        self.init(
                  cid               = cid,
                  custAddr          = custAddr,
                  merchAddr         = merchAddr,
                  merchPk           = merchPk,
                  custBal           = sp.mutez(0),
                  merchBal          = sp.mutez(0),
                  custFunding       = custFunding,
                  merchFunding      = merchFunding,
                  status            = sp.nat(AWAITING_FUNDING),
                  revLock           = sp.bytes("0x00"),
                  selfDelay         = selfDelay,
                  merchPsPkHash     = merchPsPkHash,
                  delayExpiry       = sp.timestamp(0))
 
    # addFunding is called by the customer or the merchant to fund their
    # portion of the channel (according to the amounts specified in custFunding
    # and merchFunding). The full amount must be funded in one transaction.
    @sp.entry_point
    def addFunding(self):
        sp.verify(self.data.status == AWAITING_FUNDING)
        sp.verify((self.data.custAddr == sp.sender) | (self.data.merchAddr == sp.sender))
        sp.if self.data.custAddr == sp.sender:
            sp.verify(sp.amount == self.data.custFunding)
            sp.verify(self.data.custBal == sp.tez(0))
            self.data.custBal = self.data.custFunding
        sp.if self.data.merchAddr == sp.sender:
            sp.verify(sp.amount == self.data.merchFunding)
            sp.verify(self.data.merchBal == sp.tez(0))
            self.data.merchBal = self.data.merchFunding
        # If cust and merch Balances have been funded, mark the channel as open.
        sp.if ((self.data.custBal == self.data.custFunding) & (self.data.merchBal == self.data.merchFunding)):
            self.data.status = OPEN


    # reclaimFunding allows the customer or merchant to withdraw funds
    # if the other party has not funded their side of the channel yet.
    @sp.entry_point
    def reclaimFunding(self):
        sp.verify(self.data.status == AWAITING_FUNDING)
        sp.if self.data.custAddr == sp.sender:
            sp.verify(self.data.custBal == self.data.custFunding)
            sp.send(self.data.custAddr, self.data.custBal)
            self.data.custBal = sp.tez(0)
        sp.if self.data.merchAddr == sp.sender:
            sp.verify(self.data.merchBal == self.data.merchFunding)
            sp.send(self.data.merchAddr, self.data.merchBal)
            self.data.merchBal = sp.tez(0)
 
    # expiry can be called by the merchant to initiate channel closure.
    # The customer should call custClose using the latest state. Otherwise,
    # after the delay expires, the merchant will be able to claim all the
    # funds in the channel using merchClaim.
    @sp.entry_point
    def expiry(self):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == OPEN)
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        self.data.status = EXPIRY
 
    # merchClaim can be called by the merchant if the customer has not called
    # custClose before the delay period has expired.
    @sp.entry_point
    def merchClaim(self):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == EXPIRY)
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.merchAddr, self.data.custBal + self.data.merchBal)
        self.data.custBal = sp.tez(0)
        self.data.merchBal = sp.tez(0)
        self.data.status = CLOSED

    @sp.entry_point
    def custClose(self, custBal, merchBal, revLock, s1, s2, g2, x2, y2s0, y2s1, y2s2, y2s3, y2s4):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify((self.data.status == OPEN) | (self.data.status == EXPIRY))
        merch_ps_pk_hash = sp.concat([g2, x2, y2s0, y2s1, y2s2, y2s3, y2s4])
        # Verify the merch PS Pk Hash is the same as during origination
        sp.verify(sp.sha3(merch_ps_pk_hash) == self.data.merchPsPkHash)
        # Fail if s1 is set to 0
        sp.verify(self.is_g1_not_zero(s1))
        # Retrieve the channel id and close flag
        cid = self.data.cid
        # Convert the merch PS Pk bytes into G2
        _g2 = self.convert_bytes_to_G2(g2)
        _x2 = self.convert_bytes_to_G2(x2)
        _y2s0 = self.convert_bytes_to_G2(y2s0)
        _y2s1 = self.convert_bytes_to_G2(y2s1)
        _y2s2 = self.convert_bytes_to_G2(y2s2)
        _y2s3 = self.convert_bytes_to_G2(y2s3)
        _y2s4 = self.convert_bytes_to_G2(y2s4)
        close_b = sp.bls12_381_fr(CLOSE_FLAG_B)
        # Convert balances from mutez -> fr
        cust_b = sp.local('cust_b', sp.fst(sp.ediv(custBal, sp.mutez(1)).open_some()))
        cust_bal_b = sp.local("cust_bal_b", sp.mul(cust_b.value, sp.bls12_381_fr("0x01")))
        merch_b = sp.local('merch_b', sp.fst(sp.ediv(merchBal, sp.mutez(1)).open_some()))
        merch_bal_b = sp.local("merch_bal_b", sp.mul(merch_b.value, sp.bls12_381_fr("0x01")))
        # Convert the rev_lock from bytes -> fr
        rev_lock_packed = sp.local('rev_lock_packed', sp.concat([sp.bytes("0x050a00000020"), revLock]))
        rev_lock_b = sp.local('rev_lock_b', sp.unpack(rev_lock_packed.value, t = sp.TBls12_381_fr).open_some())

        # Verify PS signature against the verified merchant pubkey
        pk = [_y2s0, _y2s1, _y2s2, _y2s3, _y2s4]
        # channel ID, close flag, rev lock, Cust Bal and Merch Bal
        msg = [cid, close_b, rev_lock_b.value, cust_bal_b.value, merch_bal_b.value]
        prod1 = sp.local('prod1', _x2)
        for i in range(0, len(msg)):
            prod1.value += sp.mul(pk[i], msg[i])
        sp.verify(sp.pairing_check([sp.pair(s1, prod1.value), sp.pair(s2, -_g2)]), message="pairing check failed")
        # Update on-chain state and transfer merchant's balance   
        self.data.custBal = custBal
        self.data.revLock = revLock
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        # Pay merchant immediately (unless amount is 0)
        # Note that all addresses must be implicit accounts (tz1), not smart contracts
        sp.if merchBal != sp.tez(0):
            sp.send(self.data.merchAddr, merchBal)
        self.data.merchBal = sp.tez(0)
        self.data.status = CUST_CLOSE
 
    # merchDispute can be called if the merchant has the secret corresponding
    # to the latest custClose state. If the secret is valid, the merchant will
    # receive the customer's balance too.
    @sp.entry_point
    def merchDispute(self, secret):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == CUST_CLOSE)
        
        # convert rev_lock in storage from LE to BE
        revlock_be = sp.local('revlock_be', sp.list([]))
        sp.for i in sp.range(0, 32):
            revlock_be.value.push(sp.slice(self.data.revLock, i, 1).open_some())
            
        sp.verify(sp.concat(revlock_be.value) == sp.sha3(secret))
        sp.send(self.data.merchAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)
        self.data.status = CLOSED
 
    # custClaim can be called by the customer to claim their balance, but only
    # after the delay period from custClose has expired.
    @sp.entry_point
    def custClaim(self):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify(self.data.status == CUST_CLOSE)
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.custAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)
        self.data.status = CLOSED
 
    # mutualClose can be called by either the customer or the merchant and
    # allows for an instant withdrawal of the funds. mutualClose requires
    # a signature from the merchant and the customer on the final state.
    @sp.entry_point
    def mutualClose(self, custBal, merchBal, merchSig):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify(self.data.status == OPEN)
        # Check merchant signature
        sp.verify(sp.check_signature(self.data.merchPk,
                                     merchSig,
                                     sp.pack(sp.record(
                                             contract_id = sp.self_address,
                                             context_string = sp.string(CONTEXT_STRING),
                                             cid = self.data.cid,
                                             custBal = custBal,
                                             merchBal = merchBal)
                                            )
                                    ))
        # Payout balances (unless amount is 0)
        # Note that all addresses must be implicit accounts (tz1), not smart contracts
        sp.if custBal != sp.tez(0):
            sp.send(self.data.custAddr, custBal)
        sp.if merchBal != sp.tez(0):
            sp.send(self.data.merchAddr, merchBal)
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
    close_flag = sp.bls12_381_fr(CLOSE_FLAG_B)
    # selfDelay = 60*60*24 # seconds in one day - 86,400
    selfDelay = 3 # seconds in one day - 86,400
    scenario.h2("On-chain installment")
    custFunding = sp.tez(5)
    merchFunding = sp.tez(0)
    g2 = sp.bytes(PUB_GEN_G2)
    y2s0 = sp.bytes(MERCH_PK0_G2)
    y2s1 = sp.bytes(MERCH_PK1_G2)
    y2s2 = sp.bytes(MERCH_PK2_G2)
    y2s3 = sp.bytes(MERCH_PK3_G2)
    y2s4 = sp.bytes(MERCH_PK4_G2)
    x2 = sp.bytes(MERCH_PK5_G2)
    merchPsPkHash = sp.bytes(MERCH_PS_PK_HASH)

    # Correct closing balances for the sample signature
    custBal = sp.tez(4)
    merchBal = sp.tez(1)

    scenario.h2("Scenario 1: escrow -> expiry -> merchClaim")
    scenario.h3("escrow")
    c1 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c1
    scenario.h3("Funding the channel")
    scenario += c1.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("expiry")
    scenario += c1.expiry().run(sender = bobMerch, now = sp.timestamp(0))
    scenario.h3("unsuccessful merchClaim before delay period")
    scenario += c1.merchClaim().run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    scenario.h3("successful merchClaim after delay period")
    scenario += c1.merchClaim().run(sender = bobMerch, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 2: escrow -> custClose -> custClaim")
    scenario.h3("escrow")
    c2 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c2
    scenario.h3("Funding the channel")
    scenario += c2.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario.p("Now the customer and merchant make a payment off chain.")
    scenario.p("For the payment to be considered complete, the customer should have received a signature from the merchant reflecting the final balances, and the merchant should have received the secret corresponding to the previous state's revLock.")
    scenario.h3("custClose")
    scenario += c2.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal,
        merchBal = merchBal,
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, now = sp.timestamp(0))
    scenario.h3("unsuccessful custClaim attempt before delay period")
    scenario += c2.custClaim().run(sender = aliceCust, now = sp.timestamp(1), valid = False)
    scenario.h3("successful custClaim after delay period")
    scenario += c2.custClaim().run(sender = aliceCust, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 3: escrow -> custClose -> merchDispute")
    scenario.h3("escrow")
    c3 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c3
    scenario.h3("Funding the channel")
    scenario += c3.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("custClose")
    scenario += c3.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust)
    scenario.h3("merchDispute called with incorrect secret")
    scenario += c3.merchDispute(sp.bytes("0x1111111111111111111111111111111111111111111111111111111111111111")).run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    # scenario.h3("merchDispute called with correct secret")
    # scenario += c3.merchDispute(sp.bytes(REV_SECRET)).run(sender = bobMerch, now = sp.timestamp(1))
 
    scenario.h2("Scenario 4: escrow -> expiry -> custClose")
    scenario.h3("escrow")
    c4 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c4
    scenario.h3("Funding the channel")
    scenario += c4.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("expiry")
    scenario += c4.expiry().run(sender = bobMerch)
    scenario.h3("custClose")
    scenario += c4.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust)
 
    scenario.h2("Scenario 5: escrow -> mutualClose")
    scenario.h3("escrow")
    c5 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c5
    scenario.h3("Funding the channel")
    scenario += c5.addFunding().run(sender = aliceCust, amount = custFunding)
    # Merchant's signature on the latest state
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c5.address,
                                                                  context_string = sp.string(CONTEXT_STRING),
                                                                  cid = cid,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario.h3("mutualClose")
    scenario += c5.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust)
 
    # scenario.h2("Scenario 6: escrow -> addCustFunding -> reclaimCustFunding")
    # scenario.h3("escrow")
    # c6 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, close_flag)
    # scenario += c6
    # scenario.h3("Customer Funding their side of the channel")
    # scenario += c6.addFunding().run(sender = aliceCust, amount = custFunding)
    # scenario.h3("Customer pulling out their side of the channel (before merchant funds their side)")
    # scenario += c6.reclaimFunding().run(sender = aliceCust)

    scenario.h2("Scenario 7: Failing tests for custClose")
    scenario.h3("escrow")
    c7 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c7
    scenario += c7.addFunding().run(sender = aliceCust, amount = custFunding)
    
    scenario.h3("Invalid merchant PS pubkey specified")
    BAD_X2 = sp.bytes("0x1304a722c780f8b4973dd4da42ef4148af2a580aa3aeddbdaba604a86ec6e62750d699bd13647089278a1e6cc490986f181529059281216c836f054f392efb90b4890a57e46f43f7dc5a8faf0fe41a1b2cd54402dd0af86b78c3a8e175daf9530a2d9d970935dc3e93463565b431d38e13456092bce8da73ed1c2274a02dd29e1e3e0dda7a6f1e0f6c67ab741b4cc20212dcab1cad18c655264f6f56a9ad1a383be2cd0c72d2fdb59ffea76cb1c9d57f84a0d82ea391579bb5e11bc61e111111")
    scenario += c7.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = BAD_X2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, valid = False)    

    scenario.h3("Invalid revLock (31 bytes instead of 32 bytes)")
    # invalid_revLock has 31 bytes instead of 32 bytes
    INVALID_REV_LOCK_FR = "0xef92f88aeed6781dc822fd6c88daf585474ab639aa06661df1fd05829b0ef7"
    scenario += c7.custClose(
        revLock = sp.bytes(INVALID_REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, valid = False)    

    scenario.h3("Invalid revLock value")
    INVALID_REV_LOCK_FR = "0x1111111111111111111111111111111111111111111111111111111111111111"
    scenario += c7.custClose(
        revLock = sp.bytes(INVALID_REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4,
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid cust balance")
    # custhBal sp.tez(5) instead of sp.tez(4)
    scenario += c7.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = sp.tez(5), 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid merch balance")
    # merchBal sp.tez(0) instead of sp.tez(1)
    scenario += c7.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = sp.tez(0), 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid closing signature length")
    # Invalid closing signature length (95 bytes instead of 96 bytes)
    INVALID_SIG_S1_G1 = "0x14f1b85366034d689d6f5399487c5129975b65aeda6bfe18560f7bf68596e631fe518fca24248c0bdd0a75fe95989df810d1d5bc02844e1e291c6de13c8879b21fffeb9229e2fa829bf442877f252af3e0fb075cbb0ebb112957a1315af49a"
    INVALID_SIG_S2_G1 = "0x0b23bd020d2e3fa293c6303493cf78f29ea908d4df930ed46910430eadc0445d33ab1f65e9ea1b74cc1be829d02c24bb0f3c3792bd177647782fd2595b376be322c0479839c56debaaa4b756c01e87f43814ecf9216302f80f05ea24cc4a6d"
    scenario += c7.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(INVALID_SIG_S1_G1), 
        s2 = sp.bls12_381_g1(INVALID_SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, valid = False)
        
    scenario.h3("Invalid closing signature value")
    INVALID_SIG_S1_G1 = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    INVALID_SIG_S2_G1 = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    scenario += c7.custClose(
        revLock = sp.bytes(REV_LOCK_FR), 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(INVALID_SIG_S1_G1), 
        s2 = sp.bls12_381_g1(INVALID_SIG_S2_G1),
        g2 = g2,
        x2 = x2,
        y2s0 = y2s0,
        y2s1 = y2s1,
        y2s2 = y2s2,
        y2s3 = y2s3,
        y2s4 = y2s4
        ).run(sender = aliceCust, valid = False)


    scenario.h2("Scenario 8: Failing tests for mutualClose")
    scenario.h3("escrow")
    c8 = ZkChannel(cid, aliceCust.address, bobMerch.address, bobMerch.public_key, custFunding, merchFunding, selfDelay, merchPsPkHash)
    scenario += c8
    scenario += c8.addFunding().run(sender = aliceCust, amount = custFunding)

    scenario.h3("Invalid signature - signing over incorrect contract_id")
    # Signing over c7.address instead of c8.address 
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c7.address,
                                                                  context_string = sp.string(CONTEXT_STRING),
                                                                  cid = cid,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario += c8.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect context string")
    # Signing over "incorrect context string" instead of "zkChannels mutual close"
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c8.address,
                                                                  context_string = sp.string("incorrect context string"),
                                                                  cid = cid,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario += c8.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect cid")
    # Signing over incorred cid (channel id)
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c8.address,
                                                                  context_string = sp.string(CONTEXT_STRING),
                                                                  cid = sp.bls12_381_fr("0x1111111111111111111111111111111111111111111111111111111111111111"),
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario += c8.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect custBal")
    # Signing over custBal sp.tez(5) instead of sp.tez(4)
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c8.address,
                                                                  context_string = sp.string(CONTEXT_STRING),
                                                                  cid = cid,
                                                                  custBal = sp.tez(5),
                                                                  merchBal = merchBal)))
    scenario += c8.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid signature - signing over incorrect merchBal")
    # Signing over merchBal sp.tez(0) instead of sp.tez(1)
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c8.address,
                                                                  context_string = sp.string(CONTEXT_STRING),
                                                                  cid = cid,
                                                                  custBal = custBal,
                                                                  merchBal = sp.tez(0))))
    scenario += c8.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid input - incorrect custBal")
    # Create valid signature
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(
                                                                  contract_id = c8.address,
                                                                  context_string = sp.string(CONTEXT_STRING),
                                                                  cid = cid,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    # Passing in custBal sp.tez(5) instead of sp.tez(4)
    scenario += c8.mutualClose(custBal = sp.tez(5), merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Invalid input - incorrect merchBal")
    # Passing in merchBal sp.tez(0) instead of sp.tez(1)
    scenario += c8.mutualClose(custBal = custBal, merchBal = sp.tez(24), merchSig = merchSig).run(sender = aliceCust, valid = False)

    scenario.h3("Verify signature used in above tests")
    scenario += c8.mutualClose(custBal = custBal, merchBal = merchBal, merchSig = merchSig).run(sender = aliceCust, valid = True)


    scenario.table_of_contents()
