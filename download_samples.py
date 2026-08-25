import os
import urllib.request


def download_file(url, output_path):
    print(f"Downloading {url} to {output_path}...")
    try:
        urllib.request.urlretrieve(url, output_path)
        print("Done.")
    except Exception as e:
        print(f"Failed to download {url}: {e}")

if __name__ == "__main__":
    # Ensure directories exist
    os.makedirs("data/evtx", exist_ok=True)
    os.makedirs("data/pcap", exist_ok=True)
    os.makedirs("data/mem", exist_ok=True)

    # EVTX sample: Lateral movement (Pass the Hash / WMI) from EVTX-ATTACK-SAMPLES
    download_file(
        "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Lateral%20Movement/LM_WMI_Win32_Process_Create.evtx",
        "data/evtx/LM_WMI_Win32_Process_Create.evtx"
    )

    # EVTX sample: Execution (PowerShell payload)
    download_file(
        "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Execution/exec_powershell_encoded_cmd.evtx",
        "data/evtx/exec_powershell_encoded_cmd.evtx"
    )

    # PCAP sample: Wireshark sample capture (e.g. malware traffic or standard HTTP)
    download_file(
        "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap",
        "data/pcap/http.cap"
    )

    print("Finished downloading initial sample datasets.")
