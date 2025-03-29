import requests
from datetime import datetime

# 🎛️ CONFIGURACIÓN
PALABRA_CLAVE = "windows"
ANIO_OBJETIVO = 2024
MAX_VULNS = 6000

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
resultados_filtrados = []
start_index = 0
page_size = 2000

while len(resultados_filtrados) < MAX_VULNS:
    params = {
        "resultsPerPage": page_size,
        "startIndex": start_index
    }

    response = requests.get(url, params=params)
    if response.status_code != 200:
        print(f"❌ Error: {response.status_code}")
        print(response.text)
        break

    data = response.json()
    cves = data.get("vulnerabilities", [])
    if not cves:
        break

    for item in cves:
        try:
            cve = item["cve"]
            description = cve["descriptions"][0]["value"].lower()
            mod_date = cve["lastModified"]

            try:
                year = datetime.strptime(mod_date, "%Y-%m-%dT%H:%M:%S.%f").year
            except ValueError:
                year = datetime.strptime(mod_date, "%Y-%m-%dT%H:%M:%S").year

            if PALABRA_CLAVE.lower() in description and year == ANIO_OBJETIVO:
                resultados_filtrados.append({
                    "cve_id": cve["id"],
                    "last_modified": mod_date,
                    "description": description
                })

        except Exception as e:
            print(f"⚠️ Error procesando una entrada: {e}")

    start_index += page_size

print(f"\n✅ Vulnerabilidades que contienen '{PALABRA_CLAVE}' y fueron MODIFICADAS en {ANIO_OBJETIVO}: {len(resultados_filtrados)}\n")

for vuln in resultados_filtrados:
   print(f"   {vuln['description'][:100]}...\n")
