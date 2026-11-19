# BGP Hijacking Mitigation with eBPF and LLM (Ollama)

Sistem mitigasi BGP Hijacking otonom berbasis LLM lokal (`qwen2.5-coder:1.5b`) dan filter kernel Linux berkecepatan tinggi (`eBPF/XDP`). Sistem ini menganalisis telemetri BGP secara real-time, mendeteksi jenis serangan (Sub-prefix Hijack, Origin Hijack), merumuskan kebijakan mitigasi, dan memasang filter CIDR prefix di level kernel.

---

## Arsitektur Sistem

```
      +---------------------+               +---------------------+
      |   Victim AS (100)   |               |   Attacker AS (300) |
      | Announce 10.100.0/16|               | Hijack 10.100.1/24  |
      +----------+----------+               +----------+----------+
                 | (eth1)                              | (eth1)
                 | 198.51.100.0/30                     | 203.0.113.0/30
                 +------------------+------------------+
                                    |
                         +----------v----------+
                         |  Transit ISP AS200  |
                         |  (Protector Node)   |
                         +----------+----------+
                                    |
          +-------------------------v-------------------------+
          |                  Host Ingress / XDP               |
          |  1. BGP Telemetry / Syslog Feed                   |
          |  2. LLM Triage Agent (qwen2.5-coder)              |
          |  3. eBPF/XDP Kernel Mitigation Engine             |
          +---------------------------------------------------+
```

---

## Dependensi

1. **Dependensi Sistem dan eBPF:**
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) python3 curl
```

2. **Container Lab:**
```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
```

3. **Ollama dan Model `qwen2.5-coder:1.5b`:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:1.5b
```

4. **Virtual environment Python:**
```bash
python3 -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
```

---

## Pemisahan Komponen: Operasional vs Pengujian

| File | Peran | Deskripsi |
|---|---|---|
| `runner.py` | **Operasional (Mitigasi)** | Agen mitigasi murni. Menerima telemetri live (via argument atau stdin pipe), memanggil LLM triage, mengompilasi `ebpf.o`, dan memasang rule XDP ke kernel. Tidak berisi data test. |
| `test.py` | **Pengujian (Benchmarking)** | Harness pengujian komprehensif. Menjalankan skenario dari `scenarios.json`, benchmark latensi LLM/eBPF, validasi akurasi, dan injeksi serangan live ke router lab. |
| `scenarios.json` | **Data Skenario Uji** | File eksternal berisi kumpulan skenario serangan (Sub-prefix, Origin Hijack, Benign) yang dapat dimodifikasi/ditambah tanpa menyentuh kode. |
| `ebpf_template.c` | **Kernel Template** | Kode C XDP untuk filtering subnet prefix dan source host. |
| `topology.clab.yml` | **Virtual Lab** | Topologi 3-node Containerlab (`AS100`, `AS200`, `AS300`). |

---

## 1. Menjalankan Agen Mitigasi (`runner.py`)

Pastikan layanan Ollama aktif:
```bash
sudo systemctl status ollama
```

### Melalui Argumen Teks / File Log Nyata:
```bash
sudo python3 runner.py "/var/log/frr/bgpd.log"
```
atau dengan teks alert langsung:
```bash
sudo python3 runner.py "BGP origin hijack detected! AS300 advertising unauthorized prefix 192.0.2.0/24"
```

### Melalui Stdin Pipe (Streaming Telemetri Real-Time):
```bash
tail -n 1 /var/log/frr/bgpd.log | sudo python3 runner.py
```

---

## 2. Menjalankan Pengujian Terstruktur (`test.py`)

Seluruh evaluasi akurasi dan benchmarking performa dilakukan melalui `test.py`:

### A. Pengujian Cepat / Dry Run (Tanpa sudo / live docker)
Mengevaluasi akurasi klasifikasi LLM dan validasi eBPF untuk seluruh skenario di `scenarios.json`:
```bash
python3 test.py --dry-run
```

### B. Pengujian Skenario Spesifik
```bash
python3 test.py --scenario sub_prefix_hijack_basic --dry-run
```

### C. Live End-to-End Attack Injection
Menjalankan injeksi rute nyata ke router `AS300`, menangkap telemetri, mengeksekusi mitigasi eBPF, lalu melakukan teardown otomatis:
```bash
sudo python3 test.py --live
```

---

## Format Menambahkan Skenario di `scenarios.json`

Anda dapat memperluas pengujian dengan menambahkan objek baru ke `scenarios.json`:

```json
{
  "name": "nama_skenario_unik",
  "description": "Deskripsi singkat skenario",
  "attack_type": "sub_prefix_hijack" | "origin_hijack" | "none",
  "expected_attack_detected": true | false,
  "expected_target_prefix": "10.x.x.x/xx" | null,
  "rogue_asn": 300 | null,
  "simulated_telemetry": "Teks log BGP atau BMP update...",
  "live_route_command": "vtysh command untuk menginjeksi rute ke AS300",
  "live_withdraw_command": "vtysh command untuk menarik rute dari AS300"
}
```

### Membersihkan Lab
```bash
sudo clab destroy -t topology.clab.yml
```
