# Network Analyzer

A simple tool to analyze a traceroute test and identify 3 possible issues:
* Path has changed during the test
* Packet loss
* High latency

The tool does 5 traceroute tests and analyze the 5 tests.


## Usage

1. Install the dependencies:
```
pip install -r requirements.txt
```


2. Change the IP used in the test
Open the file worker.py and change the variable `target_ip` (line 7)

3. Run the tool
```
python3 worker.py
```


This is the first version with very limited error treatments, etc.
It only prints a message when one issue is detected. For example:
```
{'different_path': True, 'packet_loss': {'172.68.16.42': '80.0%'}, 'high_latency': {'1.1.1.1': '107.19'}}
```
* different_path: `True` if the traceroute paths are different
* packet_loss: It will show the hop + loss percentage
* high_latency: It will show the hop + the latency 

If no issues are detected, the tool exits gracefully without message.