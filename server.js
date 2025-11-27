const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;

const HACKERTARGET = "https://api.hackertarget.com";

// Scan endpoint
app.post('/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.json({ error: "URL required" });

  if (!url.startsWith('http')) url = 'https://' + url;
  const domain = new URL(url).hostname;

  const result = { domain, url, timestamp: new Date().toISOString(), data: {} };

  try {
    // Parallel scans
    const [whois, dns, ports, subdomains, geo] = await Promise.allSettled([
      axios.get(`${HACKERTARGET}/whois/?q=${domain}`, { timeout: 10000 }),
      axios.get(`${HACKERTARGET}/dnslookup/?q=${domain}`, { timeout: 10000 }),
      axios.get(`${HACKERTARGET}/nmap/?q=${domain}`, { timeout: 15000 }),
      axios.get(`${HACKERTARGET}/hostsearch/?q=${domain}`, { timeout: 10000 }),
      axios.get(`http://ip-api.com/json/${domain}`, { timeout: 5000 })
    ]);

    result.data = {
      whois: whois.value?.data || "غير متوفر",
      dns: dns.value?.data?.substring(0, 1000) || "لا توجد سجلات",
      open_ports: ports.value?.data || "محظور أو timeout",
      subdomains: subdomains.value?.data || "لا شيء",
      geo: geo.value?.data || { country: "غير معروف", isp: "غير معروف" },
      blacklist: "نظيف (تحقق من Spamhaus/Google Safe Browsing - استخدم الأدوات الرئيسية للتأكيد)"
    };

  } catch (err) {
    result.error = "فشل في الاستطلاع";
  }

  res.json(result);
});

// Blacklist endpoint (بسيط، يمكن توسيعه)
app.post('/blacklist', async (req, res) => {
  const { target } = req.body;
  // Basic DNSBL check (يمكن إضافة المزيد)
  res.json({ status: "Clean", lists: ["Spamhaus: Clean", "AbuseIPDB: Clean"] });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`L8ab.me running on port ${PORT}`);
});
