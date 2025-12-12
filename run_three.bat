@echo off
cd marine-forensics

echo Starting Hardhat Node...
start cmd /k "cd /d %cd% && npx hardhat node"

timeout /t 5

echo Deploying Smart Contract...
start cmd /k "cd /d %cd% && npx hardhat run --network localhost scripts/deploy.js"

timeout /t 3

echo Starting Backend Server...
start cmd /k "cd /d %cd%/backend && node index.js"

echo All processes started!
pause
