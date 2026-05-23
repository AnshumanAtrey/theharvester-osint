# Testing Guide

## Local Testing (Without Docker)

1. Install dependencies:
```bash
cd theHarvester
pip install -r requirements.txt
```

2. Set up test input in `INPUT.json`

3. Run locally:
```bash
apify run
```

## Docker Testing

1. Build the Docker image:
```bash
docker build -t theharvester-actor .
```

2. Run with test input:
```bash
docker run -v $(pwd)/INPUT.json:/actor/INPUT.json theharvester-actor
```

## Test Cases

### Test 1: Basic Free Sources
```json
{
  "domain": "example.com",
  "sources": ["crtsh", "hackertarget"]
}
```

### Test 2: DNS Reconnaissance
```json
{
  "domain": "example.com",
  "sources": ["crtsh"],
  "dnsLookup": true,
  "dnsBrute": true
}
```

### Test 3: With API Keys
```json
{
  "domain": "example.com",
  "sources": ["virustotal", "shodan"],
  "virustotalApiKey": "YOUR_KEY",
  "shodanApiKey": "YOUR_KEY"
}
```

### Test 4: Active Reconnaissance
```json
{
  "domain": "example.com",
  "sources": ["crtsh"],
  "shodan": true,
  "takeOver": true,
  "shodanApiKey": "YOUR_KEY"
}
```

## Deployment

1. Push to Apify:
```bash
apify push
```

2. Test on platform with various inputs

3. Monitor logs for errors

## Troubleshooting

- Check theHarvester installation in Docker
- Verify API keys are correctly formatted
- Check output file generation
- Review subprocess logs
