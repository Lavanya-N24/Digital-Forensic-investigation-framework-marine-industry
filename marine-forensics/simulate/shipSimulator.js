const fetch = require("node-fetch");

async function sendLog() {
  const log = {
    ship: "MV-202",
    event: "Engine Overheat",
    temperature: 900,
    time: new Date().toISOString()
  };

  const res = await fetch("http://localhost:5000/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(log)
  });

  const data = await res.json();
  console.log("Submitted:", data);
}

sendLog();
