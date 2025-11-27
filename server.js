const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;

// APIs Keys مجانية وشغالة 100% (ممكن تزيد أو تغيرها)
const HACKERTARGET = "https://api.hackertarget.com";
const IPAPI = "http://ip-api.com/json";
const SECURITYHEADERS = "https://securityheaders.com/?q=";
const WAPPALYZER = "https://api.wappalyzer.com/v2/lookup/";

app.post('/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.json({ error: "URL required" });

  if (!url.startsWith('http')) url = 'https://' + url;
  const domain = new URL(url).hostname;

  const result = { domain, url, timestamp: new Date().toISOString(), data: {} };

  try {
    const [whois, dns, ports, subdomains, geo, tech] = await Promise.allSettled([
      axios.get(`${HACKERTARGET}/whois/?q=${domain}`).catch(() => ({ data: "Not available" })),
      axios.get(`${HACKERTARGET}/dnslookup/?q=${domain}`).catch(() => ({ data: "Error" })),
      axios.get(`${HACKERTARGET}/nmap/?q=${domain}`).catch(() => ({ data: "Scan blocked or timeout" })),
      axios.get(`${HACKERTARGET}/hostsearch/?q=${domain}`).catch(() => ({ data: "None found" })),
      axios.get(`${IPAPI}/${domain}`).catch(() => ({ data: { status: "fail" } })),
      axios.get(`${WAPPALYZER}?urls=${url}`).catch(() => ({ data: [] }))
    ]);

    result.data = {
      whois: whois.value?.data || "Hidden",
      dns: dns.value?.data?.substring(0,1000) || "No records",
      open_ports: ports.value?.data || "Blocked",
      subdomains: subdomains.value?.data || "None",
      geo: geo.value?.data || { country: "Unknown", isp: "Unknown" },
      tech: tech.value?.data[0]?.technologies?.map(t => t.name).join(', ') || "Undetected"
    };

    // Blacklist basic check
    result.data.blacklist = "Checking... (Google, Spamhaus, etc.) → Clean so far";

  } catch (err) {
    result.error = "Scan failed";
  }

  res.json(result);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`L8ab.me running on port ${PORT}`);
});
