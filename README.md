# 🛡️ Kernel-Callback-Studies (DASH Project) 🛡️

## 🚀 Project Overview
This project is an experimental implementation of Windows Kernel-mode callbacks using the Rust programming language. It features the **DASH Driver**, a powerful system monitor capable of detecting and terminating blacklisted processes in real-time.

> **"Gain deep insights into the Windows Kernel with Rust's safety and performance."**

## ✨ Features
- 🕵️ **Process Monitoring**: Real-time detection of process creation using `PsSetCreateProcessNotifyRoutine`.
- 🚫 **Dynamic Blacklisting**: Manage a list of restricted processes via User-mode IOCTL commands.
- 🗡️ **Instant Termination**: Automatically kills blacklisted processes upon creation.
- 🦀 **Rust-Powered**: Built with 100% Rust for enhanced memory safety in kernel space.

## 📁 Project Structure
- **`dash_driver/`**: 🧠 The core Kernel-mode driver.
- **`dash_cli/`**: 🎮 User-mode Command Line Interface to control the driver.

## 🛠️ How to Use
1. **Build the Driver**: Navigate to `dash_driver/` and build using `cargo build --release`.
2. **Build the CLI**: Navigate to `dash_cli/` and build using `cargo build --release`.
3. **Load the Driver**: Use `sc create` or your favorite driver loader.
4. **Control via CLI**: Run `dash_cli.exe` to add/remove processes from the blacklist.

## ⚠️ Educational Objectives
- Learn the fundamentals of Windows Kernel development.
- Implement and safely manage kernel-mode callbacks.
- Analyze system-level event notification in a controlled environment.

## 🛑 Disclaimer
This repository is for **educational and research purposes only**. The code provided is intended to be used in a laboratory setting to explore system architecture and security concepts. The author does not endorse or support the use of this software for malicious or unauthorized purposes.

## 📜 License
This project is licensed under the MIT License.
