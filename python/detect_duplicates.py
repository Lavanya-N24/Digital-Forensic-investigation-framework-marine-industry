import pandas as pd
import matplotlib.pyplot as plt

# Step 1: Load CSV file
data = pd.read_csv(r"C:\Users\manas\python\ais_sample.csv")

# Step 2: Show all data
print("All AIS data:")
print(data)

# Step 3: Detect duplicate Ship_IDs
duplicates = data[data.duplicated(subset=['Ship_ID'], keep=False)]
print("\nDuplicate Ship IDs (possible anomalies):")
print(duplicates)

# Step 4: Save duplicates to CSV
duplicates.to_csv(r"C:\Users\manas\python\duplicate_ships.csv", index=False)
print("\nDuplicate ships saved to duplicate_ships.csv")

# Step 5: Detect ships with suspicious speed
suspicious_speed = data[data['Speed'] > 30]  # ships moving faster than 30 knots
print("\nSuspicious speed ships:")
print(suspicious_speed)

# Step 6: Plot ships
plt.scatter(data['Longitude'], data['Latitude'], color='blue', label='All Ships')
plt.scatter(duplicates['Longitude'], duplicates['Latitude'], color='red', label='Duplicates')
plt.xlabel("Longitude")
plt.ylabel("Latitude")
plt.title("Ship Positions with Duplicates Highlighted")
plt.legend()
plt.show()
