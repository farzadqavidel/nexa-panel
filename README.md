<div align="center">

# 🚀 NEXA Panel

### A lightweight, fast, and free panel running on Cloudflare Workers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-f38020.svg)](https://workers.cloudflare.com/)
[![Database](https://img.shields.io/badge/Database-Cloudflare%20D1-orange.svg)](https://developers.cloudflare.com/d1/)

[🌐 Website / Demo](https://www.irnexa.workers.dev/) • [📣 Telegram](https://t.me/irnexa) • [🎬 YouTube](https://www.youtube.com/@IR_NEXA)

🇬🇧 **English** &nbsp;|&nbsp; 🇮🇷 [در فارسی بخوانید.](README.fa.md)

</div>

---

## 📖 Overview

**NEXA Panel** is a management panel that runs entirely on Cloudflare's free infrastructure (Workers + D1 Database) — no dedicated server required. You can spin up your own instance in just a few minutes.

## 🖼️ Screenshots


<p align="center">
  <img src="picture/1.png" width="800" alt="Preview 1"><br><br>
  <img src="picture/2.png" width="800" alt="Preview 2">
</p>

## ✨ Features

- ⚡ Fast deployment, no dedicated server needed
- 🆓 Runs on Cloudflare Workers' and D1's free tier
- 🖱️ One-click setup for non-technical users
- 🛠️ Manual setup for full configuration control
- ⏰ Automatic updates via Cron Trigger
- 🧬 VLESS protocol config generation
- 🔐 Support for both TLS and non-TLS ports
- 👥 User management section
- 💾 Automatic and manual backup section
- 🌐 IP proxy system for a static IP (not suitable for sensitive use cases such as trading or exchanges)
- 🧹 Clean IP scanner

## 🚀 Quick Deploy

Just open the deploy page and follow the steps — your panel will be live on Cloudflare's free domain:

### 👉 [Go to the deploy page](https://deploy.irnexa.workers.dev)

## 🧩 Manual Installation

If you prefer setting things up step by step with full control:

1. **Download the script**
   Download the NEXA panel script file.

2. **Create a Worker & upload the code**
   Create a new Worker on Cloudflare and upload the downloaded code onto it.

3. **Create D1 & bind it**
   Create a D1 Database and bind it to your Worker with the name `DB`.

4. **Set the `CF_API_TOKEN` variable**
   Enter the `CF_API_TOKEN` environment variable in your Worker settings.

5. **Set the Cron Trigger**
   Set a Cron Trigger for the Worker with the following value:

   ```
   30 20 * * *
   ```

## 🔗 Useful Links

<p align="center">
  <a href="https://www.irnexa.workers.dev/"><img src="https://img.shields.io/badge/🌐_Website-irnexa.workers.dev-f38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Website"></a>
  <a href="https://deploy.irnexa.workers.dev"><img src="https://img.shields.io/badge/🧷_Deploy_Page-deploy.irnexa.workers.dev-success?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Deploy Page"></a>
  <br><br>
  <a href="https://t.me/irnexa"><img src="https://img.shields.io/badge/📣_Telegram-t.me%2Firnexa-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram"></a>
  <a href="https://www.youtube.com/@IR_NEXA"><img src="https://img.shields.io/badge/🎬_YouTube-@IR__NEXA-FF0000?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube"></a>
</p>

## 💖 Support the Project

If this project has been useful to you, consider supporting it with a crypto donation 🙏

| Currency | Wallet Address |
|---|---|
| USDT (ERC20) | `0x78684D142CfD0dF27Cea2b2f62d98aBa0D4bc288` |
| TON (GRAM) | `UQBk2fhFpLgktSVucFgXdsjqNDHzHv-0GRlbN2jplnz94GZh` |
| BTC | `bc1qzzekk7y5fpzndywzk2jhmd8vv4wd7sdrq5csvu` |

## 📄 License

This project is released under the **MIT License**. See the [LICENSE](LICENSE) file or the official [MIT License](https://opensource.org/licenses/MIT) page for details.

---

<div align="center">

Made by the **NEXA** team

</div>
