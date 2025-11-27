const express = require('express');
const axios = require('axios');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const HT = "https://api.hackertarget.com";

app.post('/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.json({ error: "No target" });

  if (!url.startsWith('http')) url = 'https://' + url;
  const domain = new URL(url).hostname;

  // إذا كان الهدف هو موقعك نفسه → حظر + تحذير
  if (domain === 'l8ab.me' || domain.endsWith('.l8ab.me')) {
    return res.json({
      blacklisted: true,
      message: "BLACKLISTED DOMAIN\nTHIS IS AN AUTHORIZED PENETRATION TESTING TOOL\nSCANNING WITHOUT WRITTEN PERMISSION IS PROHIBITED",
      domain
    });
  }

  const result = { domain, ip: "", country: "", city: "", isp: "", asn: "", hosting: "", ports: "", tech: "", whois: "", subdomains: "" };

  try {
    const [ipinfo, ports, tech, whois, subdomains] = await Promise.allSettled([
      axios.get(`http://ip-api.com/json/${domain}`),
      axios.get(`${HT}/nmap/?q=${domain}`, { timeout: 15000 }),
      axios.get(`https://api.wappalyzer.com/v2/lookup/?urls=${url}`),
      axios.get(`${HT}/whois/?q=${domain}`),
      axios.get(`${HT}/hostsearch/?q=${domain}`)
    ]);

    const geo = ipinfo.value?.data || {};
    result.ip = geo.query || "Hidden";
    result.country = geo.country || "Unknown";
    result.city = geo.city || "Unknown";
    result.isp = geo.isp || "Unknown";
    result.asn = geo.as || "Unknown";
    result.hosting = geo.org || "Unknown";
    result.ports = ports.value?.data || "Scan blocked";
    result.tech = tech.value?.data[0]?.technologies?.map(t => t.name).join(', ') || "Undetected";
    result.whois = whois.value?.data?.substring(0,800) || "Hidden";
    result.subdomains = subdomains.value?.data || "None found";

  } catch (e) {
    result.error = "Partial results";
  }

  res.json(result);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`L8ab.me v3 running on ${PORT}`));
