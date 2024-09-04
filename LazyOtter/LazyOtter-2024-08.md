# About TaiChi Audit Group

TaiChi Audit Group is a team composed of DeFiHackLabs community white hat hats with extensive experience in competitive audit platforms/CTF. We are dedicated to enhancing project security coverage and providing comprehensive protection for funds.

# Introduction
LazyOtter is a risk intelligence platform designed to enhance security in DeFi. DeFi holds the potential to surpass traditional finance in safety due to blockchain technology. However, the complexity and lack of transparency in DeFi leave room for malicious actors. LazyOtter aims to provide a safer investment alternative by identifying and mitigating real risks, enabling users to invest confidently.

Disclaimer: This review does not guarantee against a hack. It is a snapshot in a time of commit (commit hash) according to the specific commit. Any modifications to the code will require a new security review.



# Risk Classification


| Severity Level | Impact: High | Impact: Medium |Impact: Low |
| -------- | -------- | -------- | --------|
| Likelihood: High     | High     | Medium     |Low    |
| Likelihood: Medium     | Medium     | Low     |Informational     |
| Likelihood: Low     | Low    | Informational     |Informational     |

##  Impact
* High: leads to a loss of assets in the protocol, or significant harm to a majority of users.
* Medium: function or availability of the protocol could be impacted  or losses to only a subset of users.
* Low: State handling, function incorrect as to spec, issues with clarity, losses will be annoying but bearable.

## Likelihood
* 	High: almost certain to happen, easy to perform, or not easy but highly incentivized.
* Medium: only conditionally possible or incentivized, but still relatively likely.
* Low: requires stars to align, or little-to-no incentive.



# Security Assessment Summary
The audit work was conducted in the time frame August 14th, 2024 to August 15th, 2024. 
One security engineer from [Cymetrics](https://x.com/cymetrics) and two white hats from [DeFiHackLabs](https://x.com/DeFiHackLabs) ([TaiChi Audit Group](https://x.com/TaiChiWeb3Sec)) participated in this audit.


The white hats are:

- [@icebear](https://x.com/iamicebear168)
- [@ret2basic](https://x.com/ret2basic)

## Project Summary

## Scope

**Summary**

| Project Name |    LazyOtter  |
|:-----:|:-------------------|
| Repository   |   https://github.com/lazyotter-finance/lazyotter-contract/blob/develop/src/vaults/RhoMarketsVault.sol           |
| Commit hash     |       73a84e99c923486f8f0d90af7b79538a8b27b1be       |
| File in Scope|     RhoMarketsVault.sol     |



**Issues Found**

| Severity            | Count | Fixed | Acknowledged |
:-----------------------------------:|:-----:|:-----:|:------------:|
| High                |  0    |   0   |      0       |
| Medium              |  1    |   1   |      0       |
| Low                 |  0    |   0   |      0       |
| Informational       |  0    |   0   |      0       |
| **Total**           |  1    |   1   |      0       |



# Findings
## Medium Risk Findings
### The calculation error in the simpleInterestFactor has harmed depositors' earnings and poses a potential systemic risk

**Description**  
In maxDeposit(), the simpleInterestFactor used to calculate interest accumulation employs inconsistent units to calculate the difference between blocks.

The [block.timestamp](https://docs.scroll.io/en/technology/chain/blocks/) and RErc20.accrualBlockNumber() have different units, and directly subtracting them leads to calculation errors.

As a result, the simpleInterestFactor is significantly underestimated, harming depositors' earnings. Parameters that rely on simpleInterestFactor, such as interestAccumulated, totalBorrows, and totalReserves, are also subject to systemic risk due to the incorrect calculations.

**Code Snippet**  

- [RhoMarketsVault.sol#L67](https://github.com/lazyotter-finance/lazyotter-contract/blob/develop/src/vaults/RhoMarketsVault.sol#L67)

**PoC**

In contract `RhoMarketsVault.sol`, add a new function named `maxDepositModified`, whose content is copied from `maxDeposit` and modify the `block.timestamp` in [line 67](https://github.com/lazyotter-finance/lazyotter-contract/blob/05678ebee77a32c41fc1599b0afd29023675d093/src/vaults/RhoMarketsVault.sol#L67) to `block.number`:

```solidity
    function maxDepositModified(address) public view returns (uint256) {
        // Supply cap of 0 corresponds to unlimited supplying
        uint256 supplyCap = comptroller.supplyCaps(address(RErc20));
        if (supplyCap == 0) {
            return type(uint256).max;
        }

        uint256 totalCash = RErc20.getCash();
        uint256 totalBorrows = RErc20.totalBorrows();
        uint256 totalReserves = RErc20.totalReserves();

        uint256 borrowRate = interestRateModel.getBorrowRate(totalCash, totalBorrows, totalReserves);

        uint256 simpleInterestFactor = borrowRate * (block.number - RErc20.accrualBlockNumber());
        uint256 interestAccumulated = (simpleInterestFactor * totalBorrows) / 1e18;

        totalBorrows = interestAccumulated + totalBorrows;
        totalReserves = (interestAccumulated * RErc20.reserveFactorMantissa()) / 1e18 + totalReserves;

        uint256 totalSupplies = totalCash + totalBorrows - totalReserves;

        if (supplyCap > totalSupplies) {
            return supplyCap - totalSupplies - 1;
        }

        return 0;
    }
```

In the test file `RhoMarketsVault.t.sol`, add a new test case `testPoCMaxDepositModified`:

```solidity
    function testPoCMaxDepositModified() public {
        uint256 totalAmount = 100 * 1e6;

        deal(address(USDC), address(this), totalAmount);
        USDC.approve(address(vault), totalAmount);
        vault.deposit(totalAmount, address(this));

        uint256 maxDeposit = vault.maxDeposit(address(this));
        console.log("maxDeposit: ", maxDeposit);

        uint256 maxDepositModified = vault.maxDepositModified(address(this));
        console.log("maxDepositModified: ", maxDepositModified);

        console.log("Difference = ", maxDepositModified - maxDeposit);
    }
```

Run the test case:

```shell
forge test --match-contract RhoMarketsVaultTest --match-test testPoCMaxDepositModified -vv
```

Output:

![testPoCMaxDepositModified output](https://hackmd.io/_uploads/H1OjGBo5C.png)

Here we can clearly see that `block.timestamp` and `block.number` produce different outputs, in particular, the current implementation (using `block.timestamp`) returns a smaller value.

Numerically, the resutls in this specific scenario looks pretty bad: `maxDepositModified` is acutally 48 times larger than `maxDeposit`!

```python
>>> 89431808427932 // 1818171499547
49
```

In other words, the "potential" of `maxDeposit` is heavily limited in current implementation, which can cause problem in integration phase. Other devs might build their own contracts and use `RhoMarketsVault.sol` as a moving part, but this surprisingly small `maxDeposit` output could lead contracts to unknown states.

**Recommendation**  

Change the `block.timestamp` in [this line](https://github.com/lazyotter-finance/lazyotter-contract/blob/05678ebee77a32c41fc1599b0afd29023675d093/src/vaults/RhoMarketsVault.sol#L67) to `block.number`:

```solidity
uint256 simpleInterestFactor = borrowRate * (block.number - RErc20.accrualBlockNumber()); 
```

**Status** 

Fixed. Commit hash : cc658bdd859014d0162b907ec77aab1a8bd4a711


