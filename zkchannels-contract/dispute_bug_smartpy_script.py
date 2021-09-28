import smartpy as sp

class ZkChannel(sp.Contract):
    def __init__(self, status: sp.TNat, revocation_lock: sp.TBls12_381_fr):
        self.init(
        status          = status,
        revocation_lock = revocation_lock
        )

    @sp.entry_point
    def merchDispute(self, revocation_secret):
        # Compute hash of the secret (in bytes), then convert to bls12_381_fr
        hash_bytes = sp.sha3(revocation_secret)
        hash_packed = sp.local('hash_packed', sp.concat([sp.bytes("0x050a00000020"), hash_bytes]))
        hash_fr = sp.local('hash_fr', sp.unpack(hash_packed.value, t = sp.TBls12_381_fr).open_some())
        # Verify the revocation secret hashes to the revocation lock
        sp.verify_equal(self.data.revocation_lock, hash_fr.value)
        self.data.status = 1

 
@sp.add_test(name = "basic")
def test():
 
    scenario = sp.test_scenario()
    scenario.table_of_contents()
 
    alice = sp.test_account("Alice")
    status = sp.nat(0)

    scenario.h2("This test passes here and on testnet")
    rev_secret = sp.bytes("0xdc2aff71a1a2975e14301e50844064a0afb2a593ccc1460e4a0dd5bb36a7d744")
    revocation_lock = sp.bls12_381_fr("0x29307053aec4c70adffde4c5706e4df68edd5548d25b2dd7b673ce15b1d5c0c4")

    mDisp = ZkChannel(status, revocation_lock)
    scenario += mDisp
    scenario += mDisp.merchDispute(rev_secret).run(sender = alice)

    scenario.h2("This test passes here and but fails on testnet")
    rev_secret2 = sp.bytes("0xdc2aff71a1a2975e14301e50844064a0afb2a593ccc1460e4a0dd5bb36a7d744")
    revocation_lock2 = sp.bls12_381_fr("0x29307053aec4c70adffde4c5706e4df68edd5548d25b2dd7b673ce15b1d5c0c4")

    mDisp2 = ZkChannel(status, revocation_lock2)
    scenario += mDisp2
    scenario += mDisp2.merchDispute(rev_secret2).run(sender = alice)
