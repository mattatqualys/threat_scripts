Subject: Qualys Threat Detection Test Kit - EKS Quick Start

Hi,

This package simulates 20 MITRE ATT&CK techniques in your EKS cluster to validate Qualys Runtime Security detections.

PREREQUISITES
- kubectl pointing at your EKS cluster
- Python 3.6+
- Qualys Runtime Sensor deployed on the cluster

HOW TO RUN
    cd "threat_scripts 1"
    python3 threatdetection_generate_data.py          # all 20 tests
    python3 threatdetection_generate_data.py 1 5      # tests 1-5 only

CLEANUP
    kubectl delete -f victim_deployment/

Note: Some commands reference hardcoded IPs from a prior test environment.
The connections will fail but detections should still trigger.
