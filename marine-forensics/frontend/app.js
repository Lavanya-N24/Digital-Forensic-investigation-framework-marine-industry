async function submitEvidence() {
  const log = JSON.parse(document.getElementById("log").value);

  const res = await fetch("http://localhost:5000/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(log)
  });

  const data = await res.json();
  document.getElementById("result").innerText = JSON.stringify(data, null, 2);
}

async function verify() {
  const id = document.getElementById("eid").value;

  const res = await fetch("http://localhost:5000/verify/" + id);
  const data = await res.json();

  document.getElementById("verify").innerText =
    JSON.stringify(data, null, 2);
}
