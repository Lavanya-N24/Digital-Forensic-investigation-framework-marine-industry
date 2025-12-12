const { exec } = require("child_process");
const path = require("path");

// Function to start Streamlit dashboard
function startPythonDashboard() {
    const pythonFolder = path.join(__dirname, "../../python");
    const pythonFile = "maritime_cybersecurity_dashboard_FINAL.py";

    const command = `start cmd /k "cd ${pythonFolder} && streamlit run ${pythonFile}"`;

    console.log("Executing:", command);

    exec(command, (error) => {
        if (error) {
            console.error("❌ Failed to start Streamlit Dashboard:", error);
        } else {
            console.log("✅ Streamlit dashboard started successfully!");
        }
    });
}

module.exports = startPythonDashboard;
