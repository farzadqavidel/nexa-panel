<div align="center">

# 🚀 NEXA Panel

### A lightweight, fast, and free panel running on Cloudflare Workers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-f38020.svg)](https://workers.cloudflare.com/)
[![Database](https://img.shields.io/badge/Database-Cloudflare%20D1-orange.svg)](https://developers.cloudflare.com/d1/)

## 🔗 Useful Links

<p align="center">
  <a href="https://www.irnexa.workers.dev/"><img src="https://img.shields.io/badge/🌐_Website-irnexa.workers.dev-f38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Website"></a>
  <a href="https://deploy.irnexa.workers.dev"><img src="https://img.shields.io/badge/🧷_Deploy_Page-deploy.irnexa.workers.dev-success?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Deploy Page"></a>
  <a href="https://farzadqavidel.github.io/nexa-panel/"><img src="https://img.shields.io/badge/📚_Documentation-farzadqavidel.github.io-8250df?style=for-the-badge&logo=gitbook&logoColor=white" alt="Documentation"></a>
  <br><br>
  <a href="https://t.me/irnexa"><img src="https://img.shields.io/badge/📣_Telegram-t.me%2Firnexa-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram"></a>
  <a href="https://www.youtube.com/@IR_NEXA"><img src="https://img.shields.io/badge/🎬_YouTube-@IR__NEXA-FF0000?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube"></a>
</p>

🇬🇧 **English** &nbsp;|&nbsp; 🇮🇷 [در فارسی بخوانید](README.fa.md)

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

## 📚 Documentation

A complete guide covering every section of the panel, from installation to advanced configuration, is available on the official documentation site:

### 👉 [View the full panel documentation](https://farzadqavidel.github.io/nexa-panel/)

## 🚀 Quick Deploy

Just open the deploy page and follow the steps — your panel will be live on Cloudflare's free domain:

### 👉 [Go to the deploy page](https://deploy.irnexa.workers.dev)

## 🧩 Manual Installation

If you prefer setting things up step by step with full control:

1. **Sign up on Cloudflare**
   Go to [Cloudflare Dashboard](https://dash.cloudflare.com) and sign up with your email.

2. **Verify your email**
   After signing up, a confirmation email will be sent to your inbox; open it and click "Confirm my account" to verify your account.

3. **Download the script**
   Download the NEXA panel script file.

4. **Create a Worker & upload the code**
   Create a new Worker on Cloudflare and upload the downloaded code onto it.

5. **Create D1 & bind it**
   Create a D1 Database and bind it to your Worker with the name `DB`.

6. **Set the `CF_API_TOKEN` variable**
   Enter the `CF_API_TOKEN` environment variable in your Worker settings.

7. **Set the Cron Trigger**
   Set a Cron Trigger for the Worker with the following value:

   ```
   30 20 * * *
   ```


## 📄 License

This project is released under the **MIT License**. See the [LICENSE](LICENSE) file or the official [MIT License](https://opensource.org/licenses/MIT) page for details.

---

<div align="center">

Made by **NEXA**

</div>