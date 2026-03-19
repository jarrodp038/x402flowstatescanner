# FlowState AI - Smart Contract Security Scanner

## x402 V2 Enabled API Service

A pay-per-use smart contract security scanner that accepts **USDC payments** via the x402 V2 protocol. AI agents and developers can scan Solidity contracts for vulnerabilities and pay per request — no subscriptions, no API keys needed.

**Built by [Flow State AI](https://flowstateai.agency)**

---

## What This Does

When deployed, your service will:

1. **Accept USDC payments** on Base network for each API call via x402 V2
2. **Appear in the x402 Bazaar** — AI agents discover and pay for your service automatically
3. **Send payments directly to your wallet** — no middleman, no facilitator fees on Base

### Pricing

| Endpoint | Price | Description |
|----------|-------|-------------|
| `/api/scan/quick` | $0.05 | Quick vulnerability scan |
| `/api/scan/deep` | $0.50 | Comprehensive security audit |
| `/api/compare` | $0.10 | Compare two contracts |
| `/api/report` | $1.00 | Professional audit report |

---

## Quick Start

### 1. Get Your Wallet Ready

You need a wallet address on Base network to receive USDC payments. Use MetaMask, Coinbase Wallet, or any EVM wallet — copy your address (starts with `0x`).

**For testing:** Get testnet USDC from the [Base Sepolia Faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet).

### 2. Configure Environment

```bash
cp env.example .env
```

Edit `.env` and add your wallet address:

```
WALLET_ADDRESS=0xYourActualWalletAddress
NETWORK=base-sepolia
FACILITATOR_URL=https://x402.org/facilitator
```

### 3. Install & Run

```bash
npm install
npm start
```

Your server starts at `http://localhost:4021`.

---

## Getting Listed in x402 Bazaar

The Bazaar is how AI agents discover your service. Here's exactly how to get listed:

### Automatic Listing (CDP Facilitator)

Your service is cataloged in the Bazaar **after the first successful payment** (verify + settle) through the CDP facilitator. There's no separate registration step.

1. Deploy your service publicly (HTTPS required)
2. Switch to production config:
   ```
   NETWORK=base
   FACILITATOR_URL=https://api.cdp.coinbase.com/platform/v2/x402
   ```
3. You'll also need CDP API keys for the production facilitator:
   ```
   CDP_API_KEY_ID=your-key-id
   CDP_API_KEY_SECRET=your-key-secret
   ```
   Get these from [portal.cdp.coinbase.com](https://portal.cdp.coinbase.com)
4. Make at least one successful paid request to trigger cataloging
5. Verify your listing: `https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources`

### Community Bazaar (Optional — Additional Visibility)

Register manually with the community discovery service for extra exposure:

```bash
curl -X POST https://x402-discovery-api.onrender.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "FlowState AI - Smart Contract Scanner",
    "url": "https://your-deployed-url.com/api/scan/quick",
    "price_usd": 0.05,
    "category": "security",
    "description": "AI-powered Solidity smart contract vulnerability scanner",
    "network": "base-mainnet"
  }'
```

---

## Testing Your Service

### Test the health endpoint (free):

```bash
curl http://localhost:4021/
```

### Test a paid endpoint (returns 402 without payment):

```bash
curl -X POST http://localhost:4021/api/scan/quick \
  -H "Content-Type: application/json" \
  -d '{"code": "pragma solidity ^0.8.0; contract Test { function withdraw() external { msg.sender.call{value: 1 ether}(\"\"); } }"}'
```

The response will be `402 Payment Required` with x402 payment instructions.

---

## Deployment Options

### Option A: Railway (Easiest)

1. Push to GitHub
2. Go to [railway.app](https://railway.app)
3. New Project → Deploy from GitHub
4. Add environment variables in dashboard
5. Railway provides a public HTTPS URL automatically

### Option B: Render (Free tier available)

1. Push to GitHub
2. Go to [render.com](https://render.com)
3. New → Web Service → Connect repo
4. Add environment variables
5. Deploy — the included `render.yaml` handles configuration

### Option C: Fly.io

```bash
curl -L https://fly.io/install.sh | sh

fly launch
fly secrets set WALLET_ADDRESS=0xYourWallet
fly secrets set NETWORK=base
fly secrets set FACILITATOR_URL=https://api.cdp.coinbase.com/platform/v2/x402
fly deploy
```

### Option D: VPS (DigitalOcean, Linode, etc.)

```bash
git clone <your-repo>
cd flowstate-contract-scanner
npm ci --omit=dev
cp env.example .env
# Edit .env with your wallet and production settings

# Run with PM2
npm install -g pm2
pm2 start index.js --name contract-scanner
pm2 save
pm2 startup
```

---

## Going to Production

### 1. Switch to Mainnet

In your `.env`:

```
NETWORK=base
FACILITATOR_URL=https://api.cdp.coinbase.com/platform/v2/x402
CDP_API_KEY_ID=your-key-id
CDP_API_KEY_SECRET=your-key-secret
```

### 2. Ensure HTTPS

Always deploy behind HTTPS. Railway, Render, and Fly.io handle this automatically.

### 3. Monitor Your Wallet

Track USDC payments at [Basescan](https://basescan.org/address/YOUR_ADDRESS).

---

## Revenue Potential

Conservative daily estimates:

- 100 quick scans/day × $0.05 = $5/day ($150/month)
- 20 deep audits/day × $0.50 = $10/day ($300/month)
- 5 reports/day × $1.00 = $5/day ($150/month)

**Estimate: $300–600/month passive income** — growing as AI agent adoption accelerates.

---

## Customization Ideas

1. **More vulnerability patterns** — flash loan attacks, front-running, sandwich attacks
2. **AI-powered analysis** — integrate Claude or GPT for deeper semantic analysis
3. **Multi-chain support** — add Solana, Polygon program analysis
4. **Webhook notifications** — alert clients on high-severity findings
5. **Historical tracking** — store and compare scan results over time

---

## Support

- **x402 Protocol**: [x402.org](https://x402.org) | [Discord](https://discord.gg/cdp) | [Docs](https://docs.cdp.coinbase.com/x402/)
- **Author**: Flow State AI — [flowstateai.agency](https://flowstateai.agency)

---

## License

MIT — Use this however you want. Build your own version. Make money.

---

*Built with x402 V2 — the future of internet payments*
