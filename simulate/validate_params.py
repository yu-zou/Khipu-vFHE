import json
with open("data/params/system_params.json") as f:
    p = json.load(f)
assert p["meta"]["aesni"] is True, "AES-NI not detected"
assert p["meta"]["security_bits"] == 256
for (s_a, g_a), (s_g, g_g) in zip(p["cpu_crypto"]["aes_gcm"]["throughput_curve"],
                                    p["cpu_crypto"]["gmac"]["throughput_curve"]):
    assert g_g > g_a, f"GMAC not faster at size {s_g}: GMAC={g_g}, AES-GCM={g_a}"
print("system_params.json validated OK")
print("AES-GCM curve:", p["cpu_crypto"]["aes_gcm"]["throughput_curve"])
print("GMAC curve:   ", p["cpu_crypto"]["gmac"]["throughput_curve"])
print("PCIe H2D:", p["pcie"]["h2d"]["bandwidth_curve"])
print("PCIe D2H:", p["pcie"]["d2h"]["bandwidth_curve"])
print("SWIOTLB p2s:", round(p["swiotlb"]["private_to_shared_gbps"], 2), "GB/s")
print("SWIOTLB s2p:", round(p["swiotlb"]["shared_to_private_gbps"], 2), "GB/s")
