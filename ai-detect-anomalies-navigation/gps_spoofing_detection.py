import pandas as pd
import matplotlib.pyplot as plt

ais_data = pd.read_csv(r"C:\Users\manas\python\ais_sample.csv")

min_lat, max_lat = 12.5, 13.5
min_lon, max_lon = 77.5, 78.0

gps_spoofed = ais_data[
    (ais_data['Latitude'] < min_lat) | (ais_data['Latitude'] > max_lat) |
    (ais_data['Longitude'] < min_lon) | (ais_data['Longitude'] > max_lon)
]

gps_spoofed.to_csv(r"C:\Users\manas\python\gps_spoofed.csv", index=False)
print("GPS Spoofed / Out-of-Bounds Ships:\n", gps_spoofed)
print("GPS spoofed ships saved to gps_spoofed.csv")

plt.scatter(ais_data['Longitude'], ais_data['Latitude'], color='blue', label='All Ships')
if not gps_spoofed.empty:
    plt.scatter(gps_spoofed['Longitude'], gps_spoofed['Latitude'], color='magenta', label='GPS Spoofed')

plt.xlabel("Longitude")
plt.ylabel("Latitude")
plt.title("GPS Spoofing Detection")
plt.legend()
plt.show()
