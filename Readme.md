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


_Disclaimer: This is the first version with very limited error treatments, etc._

