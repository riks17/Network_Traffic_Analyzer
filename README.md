# Network Traffic Analyzer

A network traffic analyzer is a software tool used to monitor, analyze, and interpret network traffic data in real-time or from recorded log files. It helps network administrators, security professionals, and system engineers to gain insights into network behavior, troubleshoot network issues, detect anomalies, and identify potential security threats.

## Installation

1. **Python Installation**: Ensure Python is installed on your system. If not, download and install it from [python.org](https://www.python.org).

2. **Scapy Installation**: Install the Scapy library using pip:

    ```bash
    pip install scapy
    ```

   After installing Scapy, download [npcap](https://npcap.com) and add the path `C:\Program Files\Npcap` to the PATH environment variable.

## Usage: Identify Wi-Fi/Ethernet Interface Name

1. Open the terminal or command prompt.
2. Navigate to the directory containing the scripts.
3. Run the `test.py` script to list available interfaces and their names.

    ```bash
    python test.py
    ```

After identifying your interface name, you can run the main scripts for packet capture, protocol analysis, anomaly detection, and traffic logging.

```bash
python packetCapture.py
python protocolAnalysis.py
python anomalyDetection.py
python trafficLogging.py
