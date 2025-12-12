async function main() {
  const [deployer] = await ethers.getSigners();

  const Registry = await ethers.getContractFactory("EvidenceRegistry");
  const registry = await Registry.deploy();
  await registry.deployed();

  console.log("Contract deployed at:", registry.address);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
