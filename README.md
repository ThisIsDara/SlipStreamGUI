# SlipStream GUI Client

## ⭐ Overview

SlipStream GUI is a user-friendly graphical interface for managing DNS-over-HTTPS tunneling sessions. Built with Python and Tkinter, it provides an intuitive way to configure, start, and monitor multiple concurrent proxy connections with real-time logging and system-wide proxy settings integration.

---

## 📥 Installation & Usage

### Option 1: Download Pre-Built Executable (Recommended)

1. Go to the [Releases page](https://github.com/ThisIsDara/SlipStreamGUI/releases)
2. Download **[SlipStream GUI v1.0.1](https://github.com/ThisIsDara/SlipStreamGUI/releases/tag/SlipStreamGUI1.0.1)**
3. Extract the archive
4. Run `SlipstreamGUI.exe`

> No Python installation required!

### Option 2: Run from Source

**Requirements:**
- Python 3.10 or higher
- Windows OS (uses Windows-specific APIs)

**Steps:**

1. Clone this repository or download `slipstream_gui.py`
2. Download the tunnel client binary:
   - [Download slipstream-binary.rar](https://github.com/ThisIsDara/SlipStreamGUI/releases/download/SlipStreamGUI1.0.1/slipstream-binary.rar)
   - Extract `slipstream-client-windows-amd64.exe` to the same folder as `slipstream_gui.py`
3. (Optional) Place `stream.ico` in the same folder for the application icon
4. Run the GUI:
   ```bash
   python slipstream_gui.py
   ```

> **Note:** Tkinter comes pre-installed with Python on Windows. No additional dependencies required!

---

## 🚀 Features

### 🔗 Connection Management
- **Multi-Session Support**: Create and manage multiple simultaneous tunneling sessions with different configurations
- **Real-Time Session Monitoring**: Track active sessions with live PID, uptime, and process status information
- **Quick Actions**: Connect, disconnect, and restart sessions with a single click
- **Configuration Persistence**: Import and export connection configurations as JSON files for easy sharing and reuse

### ⚙️ Configuration Options
- **Resolver Settings**: Configure custom DNS resolver host and port
- **Domain Configuration**: Specify the tunnel domain for your connections
- **TCP Port Management**: Set custom listening ports for SOCKS proxy (with auto-assignment option)
- **TLS Certificates**: Optional certificate support for secure connections
- **Congestion Control**: Choose between DCUBIC and BBR algorithms for optimal performance
- **Advanced Options**: Keep-alive intervals, authoritative DNS mode, and UDP GSO support

### 📋 DNS Management
- **DNS List Import**: Load DNS resolver lists from text files for quick access
- **Quick DNS Selection**: Double-click or select DNS entries to instantly populate resolver fields
- **Smart Entry Parsing**: Automatic parsing of IPv4, IPv6 (with bracket notation), and custom port formats

## 🖼️ Screenshot

<img width="936" height="866" alt="screenshot4" src="https://github.com/user-attachments/assets/d7407e91-dc0e-4e9f-bbf9-8026523886cf" />

---

### 🖥️ System Integration
- **System Proxy Control**: Enable/disable Windows system-wide SOCKS proxy with one click
- **Automatic Proxy Updates**: Seamlessly update proxy settings when starting/stopping sessions
- **Registry Integration**: Direct Windows Internet Settings integration for transparent proxy configuration
- **Process Group Management**: Efficient Windows process group handling for reliable session termination

### 📊 Monitoring & Logging
- **Live Log Viewer**: Real-time output streaming with color-coded messages (stdout, stderr, system)
- **Session Details**: View detailed information about each active session including resolver, port, and uptime
- **Process Management**: Automatic cleanup of finished sessions and continuous status updates
- **Application State Preservation**: Lock file mechanism prevents multiple instances from running simultaneously

### ✨ User Experience
- **Modern Dark Theme**: Sleek dark interface with accent colors and smooth scrolling
- **Input Validation**: Comprehensive validation of all configuration parameters with helpful error messages
- **Responsive UI**: Non-blocking operations with threaded logging and status updates for fluid interactions
- **Helpful Placeholders**: Intuitive default values and usage hints for all configuration fields

### ⚡ Performance & Reliability
- **Efficient Rendering**: Optimized terminal rendering with minimal CPU overhead
- **Non-Blocking Architecture**: Asynchronous UI updates ensure the application stays responsive
- **Memory Management**: Bounded log buffer with intelligent memory management
- **Crash Prevention**: Robust error handling and input validation throughout the application

---

## 🙏 Credit

This GUI was originally coded by **Claude Opus 4.5**. I have tweaked and customized it for my specific needs. I do not take credit for the original implementation.
