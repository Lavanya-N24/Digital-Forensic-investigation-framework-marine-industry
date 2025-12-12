// Fetch all stored evidence records
async function loadRecords() {
    const res = await fetch("http://localhost:5000/records");
    const data = await res.json();

    displayRecords(data);

    // Enable search filter
    document.getElementById("searchInput").addEventListener("input", function () {
        const keyword = this.value.toLowerCase();
        const filtered = data.filter(record =>
            JSON.stringify(record.data).toLowerCase().includes(keyword)
        );
        displayRecords(filtered);
    });
}

function displayRecords(records) {
    const container = document.getElementById("records-container");
    container.innerHTML = "";

    records.forEach(record => {
        const div = document.createElement("div");
        div.classList.add("record-card");

        const formattedJson = JSON.stringify(record.data, null, 2);

        div.innerHTML = `
            <p class="record-eid">${record.evidenceId}</p>

            <pre class="record-json">${formattedJson}</pre>

            <button class="download-btn" onclick="downloadJSON('${record.evidenceId}')">
                Download JSON
            </button>
        `;

        container.appendChild(div);
    });
}
function downloadJSON(evidenceId) {
    const id = evidenceId.replace(/^0x/, "");

    console.log("Downloading:", id);

    fetch(`http://localhost:5000/evidence/${id}`)
        .then(res => {
            if (!res.ok) throw new Error("File not found");
            return res.json();
        })
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);

            const a = document.createElement("a");
            a.href = url;
            a.download = `${id}.json`;
            a.click();
        })
        .catch(err => {
            console.error(err);
            alert("Unable to download JSON! File not found.");
        });
}

loadRecords();
