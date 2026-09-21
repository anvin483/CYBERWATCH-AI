import requests
from datetime import datetime, timezone


FALLBACK_SOLAR = {
    "windSpeed": 383,
    "density": 9.6,
    "bt": 10.2,
    "kp": 3.7,
    "source": "NOAA SWPC fallback",
    "status": "fallback",
}


def get_solar_wind():
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        speed = requests.get(
            "https://services.swpc.noaa.gov/json/rtsw/rtsw_wind_1m.json",
            timeout=8,
        )
        mag = requests.get(
            "https://services.swpc.noaa.gov/json/rtsw/rtsw_mag_1m.json",
            timeout=8,
        )
        kp = requests.get(
            "https://services.swpc.noaa.gov/json/planetary_k_index_1m.json",
            timeout=8,
        )
        speed.raise_for_status()
        mag.raise_for_status()
        kp.raise_for_status()

        speed_rows = [row for row in speed.json() if row.get("proton_speed") is not None]
        mag_rows = [row for row in mag.json() if row.get("bt") is not None]
        speed_latest = speed_rows[-1]
        mag_latest = mag_rows[-1]
        kp_latest = kp.json()[-1]
        observation_time = speed_latest.get("time_tag") or mag_latest.get("time_tag")
        updated_at = f"{observation_time}Z" if observation_time and not observation_time.endswith("Z") else observation_time

        return {
            "windSpeed": round(float(speed_latest["proton_speed"]), 1),
            "density": round(float(speed_latest["proton_density"]), 2),
            "bt": round(float(mag_latest["bt"]), 1),
            "kp": round(float(kp_latest.get("estimated_kp", kp_latest.get("kp_index", FALLBACK_SOLAR["kp"]))), 1),
            "source": f"NOAA SWPC / {speed_latest.get('source', 'RTSW')}",
            "status": "online",
            "checkedAt": checked_at,
            "updatedAt": updated_at or checked_at,
        }
    except (requests.RequestException, ValueError, TypeError, IndexError, KeyError):
        return {**FALLBACK_SOLAR, "checkedAt": checked_at, "updatedAt": None}
