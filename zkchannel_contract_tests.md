# zkchannel contract tests

## SmartPy scenario tests
Scenario 1: origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> merchClaim
Scenario 2: origination -> addFunding (cust) -> addFunding (merch) -> custClose -> custClaim
Scenario 3: origination -> addFunding (cust) -> addFunding (merch) -> custClose -> merchDispute
Scenario 4: origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> custClose
Scenario 5: origination -> addFunding (cust) -> addFunding (merch) -> mutualClose
Scenario 6: origination -> addFunding (cust) -> addFunding (merch) -> addCustFunding -> reclaimCustFunding

## Tezos sandbox pytests
origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> custClose -> custClaim
origination -> addFunding (cust) -> addFunding (merch) -> mutualClose

## PyTezos edo2net tests
origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> custClose -> merchDispute (dry run)
origination -> addFunding (cust) -> addFunding (merch) -> merchClose -> custClose -> custClaim