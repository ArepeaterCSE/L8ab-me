const express = require('express');
const axios = require('axios');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static('public'));

const HT = "https://api.hackertarget.com";

app.post('/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.json({ error: "No target" });

  if (!url.startsWith('http')) url = 'https://' + url;
  const domain = new URL(url).hostname;

  // حماية موقعك
  if (domain === 'l8ab.me' || domain.endsWith('.l8ab.me') || domain === 'l8ab.pro') {
    return res.json({
      blacklisted: true,
      message: "BLACKLISTED DOMAIN\nAUTHORIZED PENETRATION TESTING PLATFORM\nSCANNING WITHOUT EXPLICIT WRITTEN PERMISSION IS STRICTLY PROHIBITED\nVIOLATORS WILL BE REPORTED"
    });
  }

  const result = { domain };

  try {
    const [geo, ports, tech, whois, subs] = await Promise.allSettled([
      axios.get(`http://ip-api.com/json/${domain}`),
      axios.get(`${HT}/nmap/?q=${domain}`, { timeout: 18000 }),
      axios.get(`https://api.wappalyzer.com/v2/lookup/?urls=${url}`),
      axios.get(`${HT}/whois/?q=${domain}`),
      axios.get(`${HT}/hostsearch/?q=${domain}`)
    ]);

    const g = geo.value?.data || {};
    result.ip = g.query || "Hidden";
    result.location = `${g.country || "??"} • ${g.city || "Unknown"} • ${g.isp || "Unknown"}`;
    result.org = g.org || "Unknown";
    result.asn = g.as || "Unknown";
    result.ports = ports.value?.data?.trim() || "No open ports / blocked";
    result.tech = tech.value?.data[0]?.technologies?.map(t=>t.name).join(', ') || "Not detected";
    result.whois = whois.value?.data?.substring(0,1200) || "Hidden";
    result.subdomains = subs.value?.data || "None found";

  } catch (e) {
    result.error = "Partial scan completed";
  }

  res.json(result);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(process.env.PORT || 3000, () => console.log("L8ab Tools v4 Live"));
