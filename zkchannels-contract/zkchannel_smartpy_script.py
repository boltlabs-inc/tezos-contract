# This smart contract implements the zkchannel flow
import smartpy as sp
import smartpy_michelson as mi
 
# sample inputs for scenario tests
CHAN_ID_FR = "0x132418fbc6d20a33a7c244eea92c97369591bfd6c433138ae8387afb0484b707"
REV_LOCK_FR = "0x15a0ca64c4ce8a0b42726770a8d3170229978b14548ba2a67ac967dbdbcde100"
SIG_S1_G1 = "0x0d1efbfe30754c86913a75e76e7544d87a04fe843433e5a3fe05fa69d587fb65aa12bde5925f073d9500ebfeeec7082408d8bcf890c758b2eb2c5bd05ee7a20d05d2ff03a55f286435039d78b67a244b7a93d49241e3c9da13c155c89dfb2a4f"
SIG_S2_G1 = "0x068943ec6abcd6ce2d44337501c86db97617e9b76fb26dc4ca8d0494b8ecb526a552fa23293164252811f54be87a44c6066063bbf9ead6a0ef110bd094258cfad68010888041e8cffb2ffce2736dfa0fce1bf5a15c2bee0575c83395562130fb"
PUB_GEN_G2 = "0x12ade57fe34fbe7a6fdcb1fc0d828cb3a5ef7fd346f5ea5cbea3b93e4514fae09d674b4d66d3bc673c4f831c8e24b8780fffb940d1776bfa796992c6d8f3d1a009394bbaf590fa2997ff97ba4c8dca3df4a2fc1d8059c2ccf914322823d870b00770ad29db057f19b894748ea2b1b622c00d94d5a412d61c7a0797f6d5c7b5d22e7bffd3f6f87158105020f9c625941b055c2555b5dcefc3c1b40f1098a3546e655e91c94ceb5db3f3ecd405caf39b2dda56412ebf3796e54043b0cc8d30558b"
MERCH_PK0_G2 = "0x189d6846b9a2bfada602de7ebc71aa26e0ad4843bd84ced29d8ca7018978ab8e616a38bd5f23038b8c27e20d99390f4200742ab26fe59700aa9ecbfa035511c57af541a9166641088a47d09338811aecaaa399e0c95d6d8e422b318f68fac3b812808658af18177e7f3198e15279e66eebb2c5638d8c1f8a2683174fb21ae70504a1ebd3590d4f65e292c09c7b52abe810c139a8fa243314fa60922d528b240d03d2e7714a47ae3fb8999cbae79c9a0bfc3a1ed1d6cd0d313285ab29ce297087"
MERCH_PK1_G2 = "0x03624627ed9666b0a5be2789b9c9b5853d8d5cbd42ceb2159a439d83051676c63ae1fe8e7d484cdae6990cfbf61cfd6b12797a845850d7ed720f918929c8808abe9be8b21083e851d5c5c76c8988fe33c7ef6f56626262e8f2981fea3eca9c79095c0ab2f8ec415567309c89b31822467eb89f0b6005ce888da1fa9a6486ae6bb22dd5c33c81de51ae9d4b00e54ab75b01d7dab85e39a65bde59380b8ed0603dd8256677bc18f595e79a632df8bec510730c966db477313a1a6d2b581ae1700e"
MERCH_PK2_G2 = "0x01fee6b4807855ec81e09dcd9bf44fb0eb0303ffd2430779eeb351d83c52a4e073fe50f819f57dcf13b72319b4eff7a204d16de139291709f167d5fe87fbc6b8fbeeb4583118f024b75e613ff30f59b7bd0476cdef46e2f08e07cfb217f1747f180893fa0a3db549b6ec7c2c0d1f7a905c35d70c6442bdbae302c9bc0af7e6041c4f12edae5363854880e43dacbe896506196b7b32c03d1e8440137368aef2e6028da972e57c2eebb3020feb6c0997ac5a2f5c482f67ea36222287d19eedef1d"
MERCH_PK3_G2 = "0x0c0059043d9805bb179d241f4a9e92b71ffee88a2abf618b8a2fc4bdb7f60a892d47aca80527f217f0fc80184523b4911056fd8c116be111df38e4b606ddd0acfe8bc6ac252916d8f62cb739d6fb92f3ce67fe832a3d81c18580cf33223f36590a3ffb4500e2857e45726b0ac1e55fb162c61f71c4b6530272498a29b7b1b4762b1f05a58a079362886eb1bc4e6f22831861849ba23abc32cc1eb098cf75ee2588367f998e2c7bb9e3789980d424663978f2999578094e6e0ad5c788dbdc75a5"
MERCH_PK4_G2 = "0x051678c8a430375dc1782e41ae333f44d005961c8bffbcc0262bf0b42691ac2538fe7268b1eb37b253ee1848969c3f60142237a81dc49be3cd02cc3c461436840f70383b8742ac2b9f41715ddb6ea557de34f8edcf54c2fcfd8e2fcab78f8060175c94f077627d826aebcd44b22ec22004ecffc1c7a2dfa7b7ff510110df78df6f8f17c38346e07022d7073febb339c6082d97caf8ed1c50cd6d28a15752f72b296bb21c614bf7c9c0ce17639bce60b274596df53e08eec16f441e75a243626e"
MERCH_PK5_G2 = "0x186320ca37e72d3d54d8dec102289123afd9ff4c754b381f70fbedd44dad172ebe138f904b4ab75cf04073e19a43896f02c89b5bdae1b4ae12897697631c5e8cbafd2561b87b26546b899fb19f31a3421e6a4a16287ce1c66b62338e656fa2511812a67080cad41a0d63a96c88adef5bb365f893f056795468548fdaa09158a51861d82e15533804b7fde7f4940730cd12e39b220a07bef5a581f9612a3f70d57a9e63cf45b1ce58ec0f6491b8e8ef5571fe2583e8b08c67aedd632fcc4d2868"
HASH_CLOSE_B = "0x365d084a3d3a3d810606983a7690a8a119bacad72340122fa3449b1400f20f31"
 
AWAITING_FUNDING = 0
OPEN = 1
MERCH_CLOSE = 2
CUST_CLOSE = 3
CLOSED = 4
 
ZERO_IN_G1 = "0x400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
 
# chanID is a unique identifier for the channel.
# Addresses are used both for interacting with contract, and receiving payouts.
# Public keys are used for verifying signatures required for certain state transitions.
# revLock is the revocation lock used to punish a customer who broadcasts a revoked custState.
# selfDelay defines the delay (in seconds) during which the other party can counter specific state transitions.
# delayExpiry is the unix timestamp corresponding to when the delay expires.
class ZkChannel(sp.Contract):

    @sp.global_lambda
    def is_g1_zero(val):
        packed_s1 = sp.pack(val)
        packed_zero = sp.to_constant(sp.pack(sp.bls12_381_g1(ZERO_IN_G1)))
        sp.result(packed_s1 != packed_zero)

    def __init__(self, chanID, custAddr, merchAddr, custPk, merchPk, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB):
        self.init(
                  chanID            = chanID,
                  custAddr          = custAddr,
                  merchAddr         = merchAddr,
                  custPk            = custPk,
                  merchPk           = merchPk,
                  custBal           = sp.mutez(0),
                  merchBal          = sp.mutez(0),
                  custFunding       = custFunding,
                  merchFunding      = merchFunding,
                  status            = sp.nat(AWAITING_FUNDING),
                  revLock           = revLock,
                  selfDelay         = selfDelay,
                  delayExpiry       = sp.timestamp(0),
                  g2                = g2,
                  merchPk0          = merchPk0,
                  merchPk1          = merchPk1,
                  merchPk2          = merchPk2,
                  merchPk3          = merchPk3,
                  merchPk4          = merchPk4,
                  merchPk5          = merchPk5,
                  hashCloseB        = hashCloseB)
 
    # addFunding is called by the customer or the merchant to fund their
    # portion of the channel (according to the amounts specified in custFunding
    # and merchFunding).
    @sp.entry_point
    def addFunding(self):
        sp.verify(self.data.status == AWAITING_FUNDING)
        sp.if self.data.custAddr == sp.sender:
            sp.verify(sp.amount == self.data.custFunding)
            self.data.custBal = self.data.custFunding
        sp.if self.data.merchAddr == sp.sender:
            sp.verify(sp.amount == self.data.merchFunding)
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
 
    # merchClose can be called by the merchant to initiate channel closure.
    # The customer should call custClose using the latest state. Otherwise,
    # after the delay expires, the merchant will be able to claim all the
    # funds in the channel using merchClaim.
    @sp.entry_point
    def merchClose(self):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == OPEN)
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        self.data.status = MERCH_CLOSE
 
    # merchClaim can be called by the merchant if the customer has not called
    # custClose before the delay period has expired.
    @sp.entry_point
    def merchClaim(self):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == MERCH_CLOSE)
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.merchAddr, self.data.custBal + self.data.merchBal)
        self.data.custBal = sp.tez(0)
        self.data.merchBal = sp.tez(0)
        self.data.status = CLOSED

    @sp.entry_point
    def custClose(self, params):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify((self.data.status == OPEN) | (self.data.status == MERCH_CLOSE))
        # custClose inputs
        custBal = params.custBal
        merchBal = params.merchBal
        revLock = params.revLock
        s1 = params.s1
        s2 = params.s2
        # Fail if G1 is set to 0
        sp.verify(self.is_g1_zero(s1))
        # Prepare pairing check inputs
        g2 = self.data.g2
        Y0 = self.data.merchPk0
        Y1 = self.data.merchPk1
        Y2 = self.data.merchPk2
        Y3 = self.data.merchPk3
        Y4 = self.data.merchPk4
        X = self.data.merchPk5
        chanID = self.data.chanID
        close_b = self.data.hashCloseB
        cust_b = sp.local('cust_b', sp.fst(sp.ediv(custBal, sp.mutez(1)).open_some()))
        one = sp.local('one', sp.bls12_381_fr("0x01"))
        cust_bal_b = sp.local("cust_bal_b", sp.mul(cust_b.value, one.value))
        merch_b = sp.local('merch_b', sp.fst(sp.ediv(merchBal, sp.mutez(1)).open_some()))
        merch_bal_b = sp.local("merch_bal_b", sp.mul(merch_b.value, one.value))
        revLockConcat = sp.local('revLockConcat', sp.concat([sp.bytes("0x050a00000020"), revLock]))
        rev_lock_b = sp.local('rev_lock_b', sp.unpack(revLockConcat.value, t = sp.TBls12_381_fr).open_some())
        # Verify PS signature against the message
        pk = [Y0, Y1, Y2, Y3, Y4]
        msg = [chanID, rev_lock_b.value, cust_bal_b.value, merch_bal_b.value, close_b]
        prod1 = sp.local('prod1', X)
        for i in range(0, len(msg)):
            prod1.value += sp.mul(pk[i], msg[i])
        sp.verify(sp.pairing_check([sp.pair(s1, prod1.value), sp.pair(s2, -g2)]), message="pairing check failed")
        # Update on-chain state and transfer merchant's balance   
        self.data.custBal = custBal
        self.data.revLock = revLock
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        sp.send(self.data.merchAddr, merchBal)
        self.data.merchBal = sp.tez(0)
        self.data.status = CUST_CLOSE
 
    # merchDispute can be called if the merchant has the secret corresponding
    # to the latest custClose state. If the secret is valid, the merchant will
    # receive the customer's balance too.
    @sp.entry_point
    def merchDispute(self, params):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == CUST_CLOSE)
        sp.verify(self.data.revLock == sp.sha256(params.secret))
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
    def mutualClose(self, params):
        sp.verify(self.data.status == OPEN)
        # Check customer signature
        sp.verify(sp.check_signature(self.data.custPk,
                                     params.custSig,
                                     sp.pack(sp.record(
                                             chanID = self.data.chanID,
                                             custAddr = self.data.custAddr,
                                             merchAddr = self.data.merchAddr,
                                             custBal = params.custBal,
                                             merchBal = params.merchBal)
                                            )
                                    ))
        # Check merchant signature
        sp.verify(sp.check_signature(self.data.merchPk,
                                     params.merchSig,
                                     sp.pack(sp.record(
                                             chanID = self.data.chanID,
                                             custAddr = self.data.custAddr,
                                             merchAddr = self.data.merchAddr,
                                             custBal = params.custBal,
                                             merchBal = params.merchBal)
                                            )
                                    ))
        self.data.custBal = params.custBal
        self.data.merchBal = params.merchBal
        sp.send(self.data.custAddr, self.data.custBal)
        sp.send(self.data.merchAddr, self.data.merchBal)
        self.data.custBal = sp.tez(0)
        self.data.merchBal = sp.tez(0)
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
    chanID = sp.bls12_381_fr(CHAN_ID_FR)
    hashCloseB = sp.bls12_381_fr(HASH_CLOSE_B)
    custAddr = aliceCust.address
    merchAddr = bobMerch.address
    revLock = sp.sha256(sp.bytes("0x12345678aabb"))
    # selfDelay = 60*60*24 # seconds in one day - 86,400
    selfDelay = 3 # seconds in one day - 86,400
    scenario.h2("On-chain installment")
    custFunding = sp.tez(20)
    merchFunding = sp.tez(10)
    g2 = sp.bls12_381_g2(PUB_GEN_G2)
    merchPk0 = sp.bls12_381_g2(MERCH_PK0_G2)
    merchPk1 = sp.bls12_381_g2(MERCH_PK1_G2)
    merchPk2 = sp.bls12_381_g2(MERCH_PK2_G2)
    merchPk3 = sp.bls12_381_g2(MERCH_PK3_G2)
    merchPk4 = sp.bls12_381_g2(MERCH_PK4_G2)
    merchPk5 = sp.bls12_381_g2(MERCH_PK5_G2)

    scenario.h2("Scenario 1: escrow -> merchClose -> merchClaim")
    scenario.h3("escrow")
    c1 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB)
    scenario += c1
    scenario.h3("Funding the channel")
    scenario += c1.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c1.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.h3("merchClose")
    scenario += c1.merchClose().run(sender = bobMerch)
    scenario.h3("unsuccessful merchClaim before delay period")
    scenario += c1.merchClaim().run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    scenario.h3("successful merchClaim after delay period")
    scenario += c1.merchClaim().run(sender = bobMerch, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 2: escrow -> custClose -> custClaim")
    scenario.h3("escrow")
    c2 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB)
    scenario += c2
    scenario.h3("Funding the channel")
    scenario += c2.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c2.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.p("Now the customer and merchant make a payment off chain.")
    scenario.p("For the payment to be considered complete, the customer should have received a signature from the merchant reflecting the final balances, and the merchant should have received the secret corresponding to the previous state's revLock.")
    scenario.h3("custClose")
    custBal = sp.tez(18)
    merchBal = sp.tez(12)
    revLock2 = sp.bytes(REV_LOCK_FR)
    scenario += c2.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1)
        ).run(sender = aliceCust)
    scenario.h3("unsuccessful custClaim attempt before delay period")
    scenario += c2.custClaim().run(sender = aliceCust, now = sp.timestamp(1), valid = False)
    scenario.h3("successful custClaim after delay period")
    scenario += c2.custClaim().run(sender = aliceCust, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 3: escrow -> custClose -> merchDispute")
    scenario.h3("escrow")
    c3 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB)
    scenario += c3
    scenario.h3("Funding the channel")
    scenario += c3.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c3.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.h3("custClose")
    revLock2 = sp.bytes(REV_LOCK_FR) # sp.sha256(sp.bytes("0x12345678aacc"))
    scenario += c3.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1)
        ).run(sender = aliceCust)
    scenario.h3("merchDispute called with correct secret")
    # scenario += c3.merchDispute(secret = sp.bytes("0x12345678aacc")).run(sender = bobMerch, now = sp.timestamp(10))
 
    scenario.h2("Scenario 4: escrow -> merchClose -> custClose")
    scenario.h3("escrow")
    c4 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB)
    scenario += c4
    scenario.h3("Funding the channel")
    scenario += c4.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c4.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.h3("merchClose")
    scenario += c4.merchClose().run(sender = bobMerch)
    scenario.h3("custClose")
    revLock3 = sp.sha256(sp.bytes("0x12345678aacc"))
    scenario += c4.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = sp.bls12_381_g2(PUB_GEN_G2),
        merchPk0 = sp.bls12_381_g2(MERCH_PK0_G2),
        merchPk1 = sp.bls12_381_g2(MERCH_PK1_G2),
        merchPk2 = sp.bls12_381_g2(MERCH_PK2_G2),
        merchPk3 = sp.bls12_381_g2(MERCH_PK3_G2),
        merchPk4 = sp.bls12_381_g2(MERCH_PK4_G2)
        ).run(sender = aliceCust)
 
    scenario.h2("Scenario 5: escrow -> mutualClose")
    scenario.h3("escrow")
    c5 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB)
    scenario += c5
    scenario.h3("Funding the channel")
    scenario += c5.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c5.addFunding().run(sender = bobMerch, amount = merchFunding)
    # Customer's signature on the latest state
    custSig = sp.make_signature(aliceCust.secret_key, sp.pack(sp.record(chanID = chanID,
                                                                  custAddr = custAddr,
                                                                  merchAddr = merchAddr,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
 
    # Merchant's signature on the latest state
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(chanID = chanID,
                                                                  custAddr = custAddr,
                                                                  merchAddr = merchAddr,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario.h3("mutualClose")
    scenario += c5.mutualClose(custBal = custBal, merchBal = merchBal, custSig = custSig,  merchSig = merchSig).run(sender = aliceCust)
 
    scenario.h2("Scenario 6: escrow -> addCustFunding -> reclaimCustFunding")
    scenario.h3("escrow")
    c6 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4, merchPk5, hashCloseB)
    scenario += c6
    scenario.h3("Customer Funding their side of the channel")
    scenario += c6.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("Customer pulling out their side of the channel (before merchant funds their side)")
    scenario += c6.reclaimFunding().run(sender = aliceCust)
 
    scenario.table_of_contents()