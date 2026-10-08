# CNET-463 Case Study 2 - Team T01

Zero Trust Network Security Management & Hybrid Campus Lab.

Course: CNET-463 Network Security Management - Jazan University  
Instructor: Dr. Mohammed Jubur  
Team: T01  
Department / Campus: Engineering / Coastal Campus  

---

## Overview

This repository contains the practical security lab environment for Case Study 2 (Team T01). The project simulates an enterprise-grade hybrid campus network designed around the Zero Trust Architecture (ZTA) model. The lab includes micro-segmentation, centralized identity management, a custom Policy Enforcement Point (PEP), an internal Public Key Infrastructure (PKI), and isolated vendor remote access.

---

## Network Architecture & Parameters

All hosts operate within an isolated Docker bridge network using the dedicated campus subnet `10.145.0.0/16`.

### Campus Zones and IP Allocation

| Zone | Subnet | Hostnames & Addresses | Description |
| :--- | :--- | :--- | :--- |
| User Zone | `10.145.10.0/24` | `student` (`10.145.10.11`)<br>`staff` (`10.145.10.12`)<br>`guest` (`10.145.10.13`) | Campus users and untrusted client nodes |
| App Zone | `10.145.20.0/24` | `examapp` (`10.145.20.10`) | Exam web application core |
| Data Zone | `10.145.30.0/24` | `server-db` (`10.145.30.10`)<br>`server-records` (`10.145.30.20`) | Student records and exam database backends |
| Admin Zone | `10.145.40.0/24` | `admin` (`10.145.40.11`)<br>`server-support` (`10.145.40.20`) | Administrative jump box and remote support |
| DMZ | `10.145.50.0/24` | `pep` (`10.145.50.10`)<br>`idp` (`10.145.50.11`) | Zero Trust PEP gateway and Identity Provider |
| Vendor Zone | `10.145.60.0/24` | `vendor` (`10.145.60.11`) | Third-party vendor maintenance endpoint |

### Core Services Endpoints

- Exam Service (via PEP): `https://exam.engineering.t01.uni.lab:10443`
- Identity Provider (IdP): `http://10.145.50.11:8081/token`
- Records API: `http://records.engineering.t01.uni.lab:8080`
- Exam Database: Port `1521`
- Internal Certificate Authority: `Coastal Campus Internal CA (T01)`

---

## Project Structure

```text
.
├── docker-compose.yml       Container orchestration and network definitions
├── TEAM_INFO.txt            Lab specifications and assigned parameters
├── edge/
│   └── pep.py               Policy Enforcement Point (Zero Trust access control)
├── examapp/                 Exam application and listener services
├── firewall/                Host-level nftables micro-segmentation policies
│   ├── admin.nft
│   ├── examapp.nft
│   ├── server-db.nft
│   ├── server-records.nft
│   └── server-support.nft
├── idp/                     Token-based Identity Provider service
├── pki/
│   └── make_certs.sh        Campus Root CA and service certificate generation
├── tools/
│   ├── Dockerfile           Base image configuration
│   └── entrypoint.sh        Service initialization and firewall loader
└── vendor/
    └── wg0.conf             Vendor WireGuard tunnel profile
```

---

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- Bash / OpenSSL / cURL available for local testing

### 1. Initialize PKI Certificates

Generate the campus Root CA and server certificates before launching the services:

```bash
docker compose run --rm pki
```

### 2. Start the Lab Environment

Start all containers in detached mode:

```bash
docker compose up -d
```

### 3. Verify Running Services

Check the container statuses:

```bash
docker compose ps
```

### 4. Connect to a Host

To execute security tests from the student workstation:

```bash
docker compose exec student sh
```

Or connect to the administrative jump host:

```bash
docker compose exec admin sh
```

### 5. Stop the Lab

To stop and clean up all containers and volumes:

```bash
docker compose down -v
```

---

## Verification & Testing Examples

### Accessing the Exam Service via PEP

Because the domain is not published in public DNS, resolve it locally using cURL:

```bash
curl -k --resolve exam.engineering.t01.uni.lab:10443:10.145.50.10 \
     https://exam.engineering.t01.uni.lab:10443/exam
```

### Obtaining an Identity Token

```bash
curl -s -X POST http://10.145.50.11:8081/token \
     -H "Content-Type: application/json" \
     -d '{"user":"alice","role":"student","device":"managed"}'
```

### Passing the Token to PEP

```bash
TOKEN=$(curl -s -X POST http://10.145.50.11:8081/token \
  -H "Content-Type: application/json" \
  -d '{"user":"alice","role":"student","device":"managed"}' | jq -r .token)

curl -k --resolve exam.engineering.t01.uni.lab:10443:10.145.50.10 \
     -H "Authorization: Bearer $TOKEN" \
     https://exam.engineering.t01.uni.lab:10443/exam
```

---

## Security Audit & Remediation Areas

The lab is configured to evaluate Zero Trust principles through the following components:

1. Host Firewalls (`firewall/*.nft`): Ensure strict micro-segmentation and least-privilege traffic flow between subnets.
2. Policy Enforcement Point (`edge/pep.py`): Enforce token validation, prevent header spoofing, enforce device posture, and secure TLS configurations.
3. Internal PKI (`pki/make_certs.sh`): Validate certificate Subject Alternative Names (SAN), Common Names (CN), and validity windows.
4. Vendor Access Scope (`vendor/wg0.conf`): Restrict third-party tunnels strictly to designated maintenance hosts instead of broad campus subnets.