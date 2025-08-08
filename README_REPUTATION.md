# Email Header Analyser - Reputation Analysis Feature

## Overview

The Email Header Analyser now includes comprehensive IP and domain reputation checking using multiple public APIs:

- **AbuseIPDB**: IP reputation and abuse detection
- **VirusTotal**: Multi-engine threat detection for IPs and domains
- **IPQualityScore**: Proxy/VPN detection and fraud scoring

## Setup Instructions

### 1. Install Dependencies

```bash
pip install python-dotenv requests dnspython cryptography
```

### 2. Configure API Keys

Create a `.env` file in the project root with your API keys:

```env
# AbuseIPDB API Key (https://www.abuseipdb.com/api)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# VirusTotal API Key (https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# IPQualityScore API Key (https://www.ipqualityscore.com/)
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key_here
```

### 3. Get Free API Keys

All APIs offer free tiers:

- **AbuseIPDB**: 1,000 requests/day free
  - Sign up at: https://www.abuseipdb.com/api
  - Get your API key from your dashboard

- **VirusTotal**: 500 requests/day free
  - Sign up at: https://www.virustotal.com/gui/join-us
  - Get your API key from your profile

- **IPQualityScore**: 5,000 requests/month free
  - Sign up at: https://www.ipqualityscore.com/
  - Get your API key from your dashboard

### 4. Run the Application

```bash
python app.py
```

The application will run on `http://localhost:5000`

## Features

### IP Reputation Analysis

- **AbuseIPDB Integration**: Checks IP addresses against abuse database
- **VirusTotal Integration**: Multi-engine threat detection
- **IPQualityScore Integration**: Proxy/VPN detection and fraud scoring
- **Risk Scoring**: Combines results from all APIs for overall risk assessment

### Domain Reputation Analysis

- **VirusTotal Integration**: Domain threat detection
- **IPQualityScore Integration**: Disposable email and suspicious domain detection
- **Risk Assessment**: Comprehensive domain reputation scoring

### Visual Indicators

- **🟢 Green**: Low risk (0-49% score)
- **🟡 Yellow**: Medium risk (50-79% score)  
- **🔴 Red**: High risk (80-100% score)

### Risk Factors

The system flags various risk factors:

- **High abuse confidence scores**
- **Multiple security vendor detections**
- **Proxy/VPN usage**
- **Disposable email domains**
- **Suspicious domain patterns**

## API Response Examples

### IP Reputation Response
```json
{
  "ip": "192.168.1.1",
  "risk_level": "Low",
  "overall_score": 15.5,
  "flags": [],
  "abuseipdb": {
    "score": 0,
    "details": "Abuse confidence: 0%"
  },
  "virustotal": {
    "score": 0,
    "details": "0/95 security vendors flagged this IP"
  },
  "ipqualityscore": {
    "score": 0,
    "details": "Proxy: False, VPN: False, Tor: False"
  }
}
```

### Domain Reputation Response
```json
{
  "domain": "microsoft.com",
  "risk_level": "Low", 
  "overall_score": 5.0,
  "flags": [],
  "virustotal": {
    "score": 0,
    "details": "0/95 security vendors flagged this domain"
  },
  "ipqualityscore": {
    "score": 0,
    "details": "Disposable: False, Suspicious: False"
  }
}
```

## Testing

Run the reputation analysis test:

```bash
python test_reputation.py
```

This will test the reputation analysis with sample email headers and display detailed results.

## Security Notes

- API keys are loaded from environment variables for security
- Only public IPs are checked (private IPs are skipped)
- Rate limiting is handled gracefully
- Failed API calls don't break the analysis

## Troubleshooting

### Common Issues

1. **"API key not configured"**: Add your API keys to the `.env` file
2. **"API error"**: Check your internet connection and API key validity
3. **No reputation data**: Ensure you have valid API keys and the IPs/domains are public

### Rate Limiting

The free API tiers have rate limits:
- AbuseIPDB: 1,000 requests/day
- VirusTotal: 500 requests/day  
- IPQualityScore: 5,000 requests/month

The application handles rate limiting gracefully and will show "API key not configured" for rate-limited requests.

## Future Enhancements

- Caching of reputation results
- Additional reputation APIs
- Historical reputation tracking
- Custom risk scoring algorithms 