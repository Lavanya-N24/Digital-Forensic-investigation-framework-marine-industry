const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const cors = require("cors");
const fs = require("fs-extra");
const path = require("path");
const { ethers } = require("ethers");
const { exec } = require("child_process");

const app = express();
app.use(cors());
app.use(bodyParser.json());
// Serve all frontend files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "../frontend")));
const evidenceDir = path.join(__dirname, "evidence");
fs.ensureDirSync(evidenceDir);

// 🔴 UPDATE THESE AFTER DEPLOYMENT 🔴
const CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const PRIVATE_KEY = "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";
const RPC_URL = "http://127.0.0.1:8545";
// 🔴 END UPDATE 🔴

const ABI = [
  "function submitEvidence(bytes32 evidenceId, bytes32 hashValue) public",
  "function getEvidence(bytes32 evidenceId) public view returns(bytes32, uint256, address)"
];

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/* ======================================================
     🚀 NEW FUNCTION — START PYTHON STREAMLIT DASHBOARD
   ====================================================== */
app.get("/start-python", (req, res) => {
  const pythonFolder = path.join(__dirname, "../../python");
  const pythonFile = "maritime_cybersecurity_dashboard_FINAL.py";

  const command = `start cmd /k "cd ${pythonFolder} && streamlit run ${pythonFile}"`;

  console.log("Launching Streamlit using:", command);

  exec(command, (error) => {
    if (error) {
      console.error("❌ Error starting Streamlit:", error);
      return res.json({ error: "Failed to start Streamlit" });
    }
    console.log("✅ Streamlit launched successfully!");
  });

  res.json({ status: "Python Dashboard Starting..." });
});


/* ==========================
   SUBMIT EVIDENCE (same)
   ========================== */
app.post("/submit", async (req, res) => {
  try {
    const log = req.body;
    const str = JSON.stringify(log);

    const hash = sha256(str);
    const hashBytes = "0x" + hash;

    const eId = crypto.randomBytes(32).toString("hex");
    const eIdBytes = "0x" + eId;

    fs.writeJsonSync(path.join(evidenceDir, `${eId}.json`), log, { spaces: 2 });

    const tx = await contract.submitEvidence(eIdBytes, hashBytes);
    await tx.wait();

    res.send({
      message: "Evidence stored",
      evidenceId: eIdBytes,
      hash
    });
  } catch (err) {
    res.send({ error: err.message });
  }
});

/* ==========================
   VERIFY EVIDENCE (same)
   ========================== */
app.get("/verify/:id", async (req, res) => {
  try {
    const idHex = req.params.id.replace("0x", "");
    const file = path.join(evidenceDir, `${idHex}.json`);

    if (!fs.existsSync(file)) return res.send({ error: "Not found locally" });

    const localData = fs.readJsonSync(file);
    const localHash = sha256(JSON.stringify(localData));

    const [chainHash, timestamp, submitter] = await contract.getEvidence(
      "0x" + idHex
    );

    const match = chainHash.replace("0x", "") === localHash;

    res.send({
      evidenceId: req.params.id,
      localHash,
      chainHash,
      timestamp,
      submitter,
      valid: match
    });
  } catch (err) {
    res.send({ error: err.message });
  }
});

/* ==========================
   GET ALL RECORDS (same)
   ========================== */
app.get("/records", (req, res) => {
  try {
    const files = fs.readdirSync(evidenceDir);
    const records = [];

    files.forEach(file => {
      const id = file.replace(".json", "");
      const content = fs.readJsonSync(path.join(evidenceDir, file));

      records.push({
        evidenceId: "0x" + id,
        data: content
      });
    });

    res.send(records);
  } catch (err) {
    res.send({ error: err.message });
  }
});

/* ==========================
   DOWNLOAD EVIDENCE (same)
   ========================== */
app.get("/evidence/:id", (req, res) => {
  try {
    const idHex = req.params.id;
    const filePath = path.join(evidenceDir, `${idHex}.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).send({ error: "File not found" });
    }

    const jsonData = fs.readJsonSync(filePath);
    res.send(jsonData);

  } catch (err) {
    res.send({ error: err.message });
  }
});
// SERVE HOME.HTML THROUGH NODE BACKEND
/* =============================================
   SERVE HOME.HTML (ABSOLUTE PATH)
   ============================================= */
app.get("/home", (req, res) => {
  res.sendFile("C:/Users/lavan/OneDrive/Desktop/mini project/marine-forensics/frontend/home.html");
});



/* ==========================
   START BACKEND
   ========================== */
app.listen(5000, () =>
  console.log("Backend running at http://localhost:5000")
);

