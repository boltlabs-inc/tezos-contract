# zkchannel contract tests

## SmartPy scenario tests

* Scenario 1: origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> merchClaim
    * Failing test for merchClaim - claiming before timeout period
* Scenario 2: origination -> addFunding (cust) -> addFunding (merch) -> custClose -> custClaim
    * Failing test for custClaim - claiming before timeout period
* Scenario 3: origination -> addFunding (cust) -> addFunding (merch) -> custClose -> merchDispute
    * Failing test for merchDispute - incorrect rev_secret
* Scenario 4: origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> custClose
* Scenario 5: origination -> addFunding (cust) -> addFunding (merch) -> mutualClose
* Scenario 6: origination -> addFunding (cust) -> reclaimFunding (cust)

Failing tests for custClose
* Invalid revLock (31 bytes instead of 32 bytes)
* Invalid revLock value
* Invalid cust balance
* Invalid merch balance
* Invalid closing signature length
* Invalid closing signature value

Failing tests for mutualClose
* Invalid signature - signing over incorrect contract_id
* Invalid signature - signing over incorrect context string
* Invalid signature - signing over incorrect cid
* Invalid signature - signing over incorrect custBal
* Invalid signature - signing over incorrect merchBal
* Invalid input - incorrect custBal
* Invalid input - incorrect merchBal
## Tezos sandbox pytests

* origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> custClose -> custClaim
* origination -> addFunding (cust) -> addFunding (merch) -> mutualClose

## PyTezos edo2net tests

* origination -> addFunding (cust) -> reclaimFunding (cust) -> addFunding (cust) -> addFunding (merch) -> expiry -> merchClaim
* origination -> addFunding (cust) -> addFunding (merch) -> expiry -> custClose -> merchDispute
* origination -> addFunding (cust) -> merchClose -> custClose -> custClaim
