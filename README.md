# Email Header Analyser - Enhanced Edition

A comprehensive web application that analyses email headers to explain and evaluate DKIM, SPF, DMARC authentication methods, with advanced features including geolocation analysis, threat intelligence, and network routing analysis.

## 🚀 **New Enhanced Features**

### 📄 **PDF Report Generation**
- **Comprehensive Reports**: Generate detailed PDF reports of email header analysis
- **Professional Formatting**: Clean, structured reports suitable for documentation
- **Complete Analysis**: Includes all authentication results, security warnings, and recommendations
- **Forensic Documentation**: Raw headers included for forensic analysis
- **Easy Download**: One-click PDF download from the web interface

### 🌍 **Geolocation Analysis**
- **IP Address Mapping**: Identifies and maps all IP addresses found in email headers
- **Geographic Location**: Shows country, city, and region information for each IP
- **ISP Analysis**: Displays Internet Service Provider information
- **Risk Assessment**: Evaluates geographic risk factors and suspicious patterns
- **Real-time Lookup**: Uses ipapi.co for accurate geolocation data

### 🛡️ **Threat Intelligence**
- **Suspicious Pattern Detection**: Identifies common phishing and spam indicators
- **Content Analysis**: Scans for suspicious keywords and patterns
- **Domain Analysis**: Evaluates sender domains for potential threats
- **Risk Scoring**: Provides threat level assessment (Low/Medium/High)

### 🌐 **Network Analysis**
- **Routing Path Visualization**: Shows the complete email routing path
- **Hop Analysis**: Analyses each routing hop for suspicious activity
- **Network Security**: Identifies unusual routing patterns
- **Server Validation**: Checks for unknown or suspicious servers

### 📊 **Enhanced Security Scoring**
- **Multi-factor Assessment**: Combines authentication, geolocation, and threat intelligence
- **Risk Level Classification**: Provides comprehensive risk assessment
- **Actionable Recommendations**: Generates specific improvement suggestions
- **Visual Risk Indicators**: Color-coded risk levels for easy interpretation

## Features

### 🔍 **Email Header Analysis**
- **DKIM (DomainKeys Identified Mail)**: Analyses cryptographic signatures to verify email authenticity
- **SPF (Sender Policy Framework)**: Checks if the sending server is authorised for the domain
- **DMARC (Domain-based Message Authentication, Reporting and Conformance)**: Evaluates overall email authentication policy

### 📊 **Security Scoring**
- Calculates overall email security score (0-100%)
- Provides security level assessment (Poor, Fair, Good, Excellent)
- Visual score display with percentage and recommendations
- **NEW**: Risk assessment with threat level indicators

### 🎨 **Modern UI**
- Beautiful, responsive design with gradient backgrounds
- Interactive cards for each authentication method
- Real-time analysis with loading animations
- Sample headers for testing different scenarios
- **NEW**: Advanced analysis sections with geolocation maps and threat indicators

### 📚 **Educational Content**
- Detailed explanations of each authentication method
- Practical recommendations for improving email security
- Sample headers demonstrating good, poor, and no authentication
- **NEW**: Threat intelligence explanations and security best practices

### 📄 **PDF Report Generation**
- **One-click PDF Download**: Generate comprehensive reports directly from the web interface
- **Professional Documentation**: Clean, structured reports suitable for security documentation
- **Complete Analysis**: Includes all authentication results, security warnings, and recommendations
- **Forensic Records**: Raw headers included for forensic analysis and record-keeping
- **Multiple Formats**: Works with both text input and .eml file uploads

## What are DKIM, SPF, and DMARC?

### 🔑 **DKIM (DomainKeys Identified Mail)**
- **Purpose**: Uses cryptographic signatures to verify email authenticity
- **How it works**: The sending server adds a digital signature to the email. Receiving servers verify this signature using the sender's public key stored in DNS
- **Benefits**: Prevents email tampering and spoofing
- **Example**: `DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector;...`

### 🛡️ **SPF (Sender Policy Framework)**
- **Purpose**: Prevents email spoofing by specifying authorised sending servers
- **How it works**: Domain owners publish a list of authorised IP addresses in DNS. Receiving servers check if the sending IP is in this list
- **Benefits**: Stops unauthorised servers from sending emails on behalf of your domain
- **Example**: `Received-SPF: pass (google.com: domain designates 192.168.1.1 as permitted sender)`

### ✅ **DMARC (Domain-based Message Authentication, Reporting and Conformance)**
- **Purpose**: Combines SPF and DKIM to provide comprehensive email authentication policy
- **How it works**: Tells receiving servers what to do with emails that fail SPF and DKIM checks (reject, quarantine, or accept)
- **Benefits**: Provides reporting and policy enforcement for email authentication
- **Example**: `Authentication-Results: mx.google.com; dmarc=pass header.from=example.com;`

## Installation

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd email-header-analyzer
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API keys (optional but recommended for full functionality)**
   
   Create a `.env` file in the project root with the following API keys:
   ```
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key
   TALOS_API_KEY=your_talos_api_key
   ```
   
   **API Key Sources:**
   - **AbuseIPDB**: Free tier available at https://www.abuseipdb.com/
   - **VirusTotal**: Free API key at https://www.virustotal.com/
   - **IPQualityScore**: Free tier at https://www.ipqualityscore.com/
   - **Talos Intelligence**: Cisco's threat intelligence at https://talosintelligence.com/

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open your browser**
   Navigate to `http://localhost:5000`

## Usage

### Basic Analysis
1. Open the web application in your browser
2. Paste email headers into the text area
3. Click "Analyse Headers"
4. Review the results and recommendations

### Enhanced Analysis Features
The application now provides comprehensive analysis including:

#### 🌍 **Geolocation Analysis**
- **IP Address Detection**: Automatically finds all IP addresses in headers
- **Geographic Mapping**: Shows location, country, and ISP information
- **Risk Assessment**: Evaluates geographic risk factors
- **Suspicious Pattern Detection**: Identifies VPN, proxy, or anonymous services

#### 🛡️ **Threat Intelligence**
- **Content Scanning**: Detects suspicious keywords and patterns
- **Domain Analysis**: Evaluates sender domain reputation
- **Pattern Recognition**: Identifies common phishing indicators
- **Risk Scoring**: Provides threat level assessment

#### 🌐 **Network Analysis**
- **Routing Visualization**: Shows complete email path
- **Hop Analysis**: Examines each routing step
- **Security Validation**: Checks for suspicious routing patterns
- **Server Identification**: Validates intermediate servers

### Sample Headers
The application includes sample headers for testing:
- **Good Authentication**: Shows headers with proper DKIM, SPF, and DMARC
- **Poor Authentication**: Shows headers with neutral or missing authentication
- **No Authentication**: Shows basic headers without authentication methods

### Understanding Results

#### Security Score
- **Excellent (80-100%)**: All three authentication methods are properly configured
- **Good (60-79%)**: Most authentication methods are working
- **Fair (40-59%)**: Some authentication methods are missing or failing
- **Poor (0-39%)**: Most or all authentication methods are missing

#### Risk Assessment
- **Low Risk**: Minimal security concerns detected
- **Medium Risk**: Some security issues identified
- **High Risk**: Multiple security vulnerabilities detected

#### Status Indicators
- **Pass**: Authentication check passed successfully
- **Fail**: Authentication check failed
- **Neutral**: No clear policy or neutral result
- **Not Found**: Authentication method not present in headers

## How to Get Email Headers

### Gmail
1. Open the email
2. Click the three dots (⋮) in the top right
3. Select "Show original"
4. Copy the headers from the top of the page

### Outlook
1. Open the email
2. Click "File" → "Properties"
3. Copy the "Internet headers" section

### Apple Mail
1. Open the email
2. Press `Cmd + Shift + I` (or View → Message → All Headers)
3. Copy the headers

### Thunderbird
1. Open the email
2. Press `Ctrl + U` (or View → Message Source)
3. Copy the headers from the top

## Improving Email Security

### For Domain Owners
1. **Implement SPF**: Add SPF record to your DNS
   ```
   TXT @ "v=spf1 include:_spf.google.com ~all"
   ```

2. **Set up DKIM**: Configure DKIM signing on your email server
   - Generate key pair
   - Add public key to DNS
   - Configure server to sign outgoing emails

3. **Create DMARC Policy**: Add DMARC record to DNS
   ```
   TXT _dmarc "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
   ```

4. **Monitor Geolocation**: Review sending server locations for unusual patterns

5. **Threat Intelligence**: Implement content filtering for suspicious patterns

### For Email Users
1. Check email headers for authentication results
2. Be cautious of emails with poor authentication scores
3. Review geolocation data for suspicious origins
4. Report suspicious emails to your IT department
5. Use the threat intelligence features to identify potential risks

### PDF Report Generation
1. **Analyse Headers**: Paste email headers or upload a .eml file
2. **Review Results**: Examine the comprehensive analysis results
3. **Download PDF**: Click the "Download PDF Report" button
4. **Save Report**: The PDF will be automatically downloaded with a timestamp
5. **Documentation**: Use the PDF for security documentation and forensic records

**PDF Report Contents:**
- Executive summary with security score and risk assessment
- Detailed authentication analysis (DKIM, SPF, DMARC)
- Headers found with explanations
- Security warnings and compliance issues
- Reputation analysis results
- Network analysis and routing information
- Recommendations for improvement
- Raw email headers for forensic analysis

## Technical Details

### Dependencies
- **Flask**: Web framework for the application
- **dnspython**: DNS resolution for authentication checks
- **cryptography**: Cryptographic operations for DKIM verification
- **python-dotenv**: Environment variable management
- **requests**: HTTP requests for geolocation lookups
- **geoip2**: IP geolocation database access
- **ipaddress**: IP address validation and manipulation
- **reportlab**: PDF generation for comprehensive reports

### Architecture
- **Backend**: Python Flask application with REST API
- **Frontend**: Modern HTML/CSS/JavaScript with responsive design
- **Analysis**: Regex-based header parsing with educational explanations
- **Geolocation**: Real-time IP geolocation using ipapi.co
- **Threat Intelligence**: Pattern-based threat detection

### Security Features
- Input validation and sanitization
- Error handling for malformed headers
- Secure HTTP headers and CSRF protection
- Rate limiting for geolocation API calls
- Privacy-conscious data handling

### API Integration
- **ipapi.co**: Free geolocation service for IP address lookup
- **AbuseIPDB**: IP reputation and threat intelligence
- **VirusTotal**: Domain and IP threat intelligence
- **IPQualityScore**: Email and domain quality assessment
- **Talos Intelligence**: Cisco's threat intelligence for domain reputation
- **Extensible**: Easy to add additional threat intelligence APIs
- **Caching**: Implements basic caching for performance
- **Error Handling**: Graceful fallbacks for API failures

## Advanced Features

### Geolocation Analysis
The application now provides detailed geolocation analysis:

- **IP Address Detection**: Automatically extracts all IP addresses from headers
- **Geographic Mapping**: Shows city, region, and country information
- **ISP Analysis**: Displays Internet Service Provider details
- **Risk Assessment**: Evaluates geographic risk factors
- **Suspicious Pattern Detection**: Identifies VPN, proxy, or anonymous services

### Threat Intelligence
Advanced threat detection capabilities:

- **Content Analysis**: Scans for suspicious keywords and patterns
- **Domain Reputation**: Evaluates sender domain trustworthiness
- **Pattern Recognition**: Identifies common phishing indicators
- **Risk Scoring**: Provides comprehensive threat assessment

### Network Analysis
Complete network routing analysis:

- **Routing Path**: Visualizes the complete email delivery path
- **Hop Analysis**: Examines each routing step for security
- **Server Validation**: Checks intermediate servers for suspicious activity
- **Network Security**: Identifies unusual routing patterns

## Contributing

Feel free to contribute to this project by:
- Reporting bugs
- Suggesting new features
- Improving documentation
- Adding more authentication methods
- Enhancing threat intelligence capabilities
- Contributing to geolocation analysis

## License

This project is open source and available under the MIT License.

## Support

For questions or issues, please open an issue on the project repository or contact the development team.

---

**Note**: This tool is for educational and analysis purposes. Always verify email authenticity through multiple methods and consult with security professionals for production environments. The geolocation features use external APIs and should be used in accordance with their terms of service. 