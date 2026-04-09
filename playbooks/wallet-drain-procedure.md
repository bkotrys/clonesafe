# Safe crypto wallet migration after compromise

> **Priority:** HIGHEST among rotation steps. Crypto theft is the only category of loss that is fully irreversible. Every other credential can be rotated; stolen funds cannot be recovered.
>
> **Time budget:** 30-60 minutes depending on how many chains/wallets you hold.

This playbook applies if you had any crypto wallets (browser extension or desktop) installed on the compromised machine at the time of incident:

- MetaMask
- Phantom
- Rabby
- Keplr
- Coinbase Wallet
- Trust Wallet
- Brave Wallet
- Exodus, Electrum, Sparrow, Bitcoin Core, Atomic, Guarda, any other desktop wallet
- Hardware wallets are handled differently — see [Hardware wallet users](#hardware-wallet-users) below

---

## The core assumption

**Assume the attacker has your encrypted wallet vault file(s)** and is attempting to brute-force your password offline right now. If your wallet password is weak-to-medium, the seed phrase recovery is a matter of hours to days. If it's strong (14+ random characters), it's computationally expensive but still possible given enough time.

**Treat every second as borrowed time.** Drain first, understand later.

---

## Before you start

Gather on your phone (NOT on the compromised machine):

- [ ] A list of every chain you've ever used (Ethereum, Polygon, Arbitrum, Optimism, Base, BSC, Avalanche, Solana, Bitcoin, etc.)
- [ ] A list of every wallet you've set up over the years
- [ ] Any staked/locked positions you need to unstake
- [ ] Any NFTs you care about (collection names, not individual IDs)
- [ ] Any LP positions, lending positions, pending orders

Write this list before you start. You'll work through it systematically.

---

## Step 1 — Create fresh wallets on a clean device (NOT the compromised machine)

**Use your phone.** If MetaMask / Phantom / etc. are already installed on your phone, they were NOT touched by the Node.js attack on your laptop — phone storage is separate, containerized, and inaccessible to desktop malware.

**If your phone doesn't have the wallets:**
1. Install the official apps from the App Store / Play Store (not via a link someone sent you)
2. Verify the publisher matches the real company (e.g., ConsenSys Software for MetaMask, Phantom Technologies Inc. for Phantom)
3. Create a fresh wallet → **write the new seed phrase on PAPER, not digitally**
4. Do NOT photograph the seed phrase. Do NOT store it in cloud-synced notes. Do NOT type it anywhere except the wallet app itself.

**Alternative: hardware wallet**
- If you have a Ledger / Trezor / Keystone, initialize it now on a clean device. This is the gold standard.
- The seed phrase for hardware wallets never leaves the device.

**What you need from the new wallets:** the **receive addresses**. Copy them to your phone's notes app.

---

## Step 2 — Drain the old wallets, chain by chain

**IMPORTANT:** You will need to unlock the old wallets one last time to send funds out. This is an acceptable risk because (a) the funds are leaving anyway, and (b) even if a keylogger captures your password now, the wallet will be empty within seconds.

You can do this on the compromised machine OR on your phone. If on phone: import the old seed temporarily, send funds to new address, then remove the account. If on the compromised machine: unlock, drain, never unlock again.

### For every EVM chain (Ethereum, Polygon, Arbitrum, Optimism, Base, BSC, Avalanche, etc.)

Work each chain separately:

1. Switch network in MetaMask to the chain you're draining
2. **Send non-ETH/BNB/MATIC tokens first** (ERC-20s, NFTs, LP positions, staked tokens)
3. **Unstake any locked positions** if the unstake is fast (<5 minutes). If unstake has a long cooldown, you'll have to come back in 7-21 days to claim.
4. **Send the native gas token last** (ETH on Ethereum, MATIC on Polygon, BNB on BSC, etc.). Leave yourself a tiny amount for gas if you need multiple transactions — but send the rest.
5. **Verify the transaction confirmed on the block explorer** before moving to the next chain. Don't trust the wallet UI alone.

Common chains to check (don't skip any you've touched):
- Ethereum mainnet
- Polygon (MATIC)
- Arbitrum One
- Optimism
- Base
- BNB Smart Chain
- Avalanche C-chain
- Fantom
- Linea
- zkSync Era
- Scroll
- Mantle
- Blast
- Mode

### For Solana

1. Send SPL tokens first (any fungible tokens that aren't native SOL)
2. Send NFTs (each is a separate transaction)
3. Send SOL last, leaving a tiny amount for gas if you need multiple TXs, then send the rest

### For Bitcoin

- Send the full balance in one transaction if possible
- If you have UTXOs across multiple addresses, send from each

### For Cosmos ecosystem (Keplr, Leap)

- Unstake delegations (21-day unbonding on most chains — you'll have to come back)
- Send liquid balance immediately
- Work each chain: Cosmos Hub, Osmosis, Celestia, Injective, Dymension, etc.

---

## Step 3 — Revoke token approvals on the old wallets

**This step is often skipped and it's critical.** When you use DeFi, you grant contract allowances to DEXes, lending protocols, and bridges. If the attacker has your seed phrase, they can call those approved contracts to drain any future tokens you receive on the old addresses.

Go to **https://revoke.cash**, connect the old wallet (each one, each chain), and revoke ALL approvals. Yes, all of them. You'll re-approve specific ones later from the new wallets if you need them.

Cost: a few cents per revoke on L2s, more on mainnet. Do it anyway. Budget $5-50 total depending on how many approvals.

For Solana: use **https://solscan.io** or **https://solana.fm** → connect wallet → token approvals → revoke. SPL token approval model is different but you should still clean up.

---

## Step 4 — Abandon the old wallets

**Do NOT:**
- Reuse the old seed phrase in any new wallet
- Import the old seed into the new device "just in case"
- Keep the old wallet as a "savings account" — it's compromised forever
- Send any future funds to the old addresses — the attacker can drain them instantly

**DO:**
- Delete the wallet from the browser extension (or leave it but never unlock it)
- If you had labels like "main wallet" / "savings", rename them to "COMPROMISED - DO NOT USE"
- In your password manager, mark the old wallet as compromised

---

## Step 5 — Update any service that whitelisted the old address

Some services whitelist withdrawal addresses (exchanges, OTC desks, payment processors). Update each one to your new addresses:

- Centralized exchanges (Binance, Coinbase, Bybit, KuCoin, Kraken, OKX, Bitstamp, etc.) — withdrawal whitelists
- Payment processors (BitPay, Coinbase Commerce)
- OTC desks you've used
- DEX aggregators with saved addresses (1inch Pro, Matcha, CoWSwap history)
- Any smart contract that holds funds destined for "your" address

---

## Hardware wallet users

If you used a hardware wallet with MetaMask/Phantom/etc. on the compromised machine:

- **Your seed phrase is safe** — it never left the hardware device
- **Your funds are safe** — transactions require physical confirmation on the device
- **But:** the attacker may have scraped your public addresses and is now watching them for phishing opportunities

What to do:
- You do NOT need to drain to a new hardware wallet
- But you should:
  - Be hyper-vigilant for phishing impersonating Ledger/Trezor/your hardware wallet brand for the next 90 days
  - Never click "update firmware" links from emails
  - Never type your seed phrase anywhere, ever (you should never have to)
  - Check your addresses periodically for any unexpected activity

---

## After you're done

- [ ] All funds moved from old wallets to new wallets on every chain you've touched
- [ ] Approvals revoked on revoke.cash (EVM) and equivalent (Solana, Cosmos)
- [ ] Old wallets labeled as compromised, never to be used again
- [ ] New wallet addresses updated in every service that whitelists withdrawal addresses
- [ ] New seed phrases written on paper only, stored in a secure location (safe, safety deposit box, fireproof box)

Now go to [`github-audit.md`](github-audit.md) next.

---

## Common mistakes to avoid

1. **"I'll just keep the old wallet for small amounts"** — NO. The attacker can drain it instantly with the seed phrase. Any future deposit is immediately stolen.

2. **"I'll import the old seed to the new app first"** — NO. Creating a truly new wallet means a truly new seed. Don't mix.

3. **"I'll skip the chains I haven't used recently"** — CHECK THEM ANYWAY. Many victims lose funds on forgotten chains (especially Polygon, BSC, Arbitrum) because they only drained mainnet.

4. **"I'll screenshot the seed phrase just for backup"** — NO. Screenshots end up in iCloud / Google Photos / cloud sync. Paper only.

5. **"I'll skip revoke.cash to save gas fees"** — NO. Stale approvals are how drainers continue stealing from victims weeks after the initial breach.

6. **"I'll drain tomorrow, I'm tired"** — **NO.** Drain NOW. Sleep after. If your password is brute-forced overnight, everything is gone.
