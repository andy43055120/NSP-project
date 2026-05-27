# NSP-project

# Project1: Sentinel Virus Scanner

A functional signature-based virus scanner developed for the Network Security project.

## Features

- SHA256 signature detection
- HEX pattern detection
- Heuristic analysis
- Recursive directory scanning
- Scan report generation

## Project Structure

```text
Project1
├── scanner
│   ├── hash_scanner.py
│   ├── pattern_scanner.py
│   ├── heuristic.py
│   └── report.py
├── signatures
│   └── signatures.json
├── test_files
└── main.py
```

## Detection Methods

### Signature-Based Detection
- SHA256 hash matching
- HEX pattern matching

### Heuristic Analysis
Suspicious keywords:

- os.system
- subprocess
- eval
- exec
- powershell
- cmd.exe

## Run

Create virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install pandas tqdm colorama
```

Run scanner:

```bash
python main.py
```

## Example Output

```text
Threats found:

{'path':'test_files/mock.exe',
'threat':'Mock-Trojan',
'severity':'Medium',
'method':'HEX'}

{'path':'test_files/eicar.txt',
'threat':'EICAR-Test-File',
'severity':'Low',
'method':'SHA256'}
```


# Project: APT Agent

## Run
Build:
```bash
cd lab
docker build -t ic_image ./IC #docker image
 ./docker.sh 3 # Create Docker containers for different project
./docker_ec.sh # Create EC and login
```

Run:
```bash
#in EC
./grader.sh
```

## Example Output
```text
root@43b6fac13473:/# ./grader.sh
[*] Round 1 start
[+] Exploit successful! Grading ends.
[*] Grading done
Total time: 1 seconds
root@43b6fac13473:/# ls /shared/
blogic  config.data  coredump  success.txt  triage_hint.txt
```