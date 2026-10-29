# BGP Hijacking Mitigation with eBPF and Ollama

## Dependensi

Pastikan tools dan dependensi berikut sudah terinstall di sistem (maaf ini spesifik Ubuntu):

1. **Dependensi Sistem dan eBPF:**
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) python3 curl
```


2. **Container Lab:**
```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
```


3. **Ollama dan Model qwen2.5-coder:1.5b:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:1.5b
```

4. **Virtual environment Python:**
```bash
python3 -m venv .venv
./.venv/bin/activate
pip3 install -r requirements.txt
```


## Cara Menjalankan
Deploy jaringan virtual simulasi BGP:
```bash
sudo clab deploy -t topology.clab.yml
```

Pastikan layanan latar belakang Ollama berjalan dan siap menerima request pada port `11434` (atau bisa disesuaikan jika butuh port lain):

```bash
sudo systemctl status ollama
```

Eksekusi kode wrapper Python yang akan menjalankan prototype (butuh sudo privilege karena melakukan namespace attach/detach):
```bash
sudo python3 runner.py
```

Jika sudah selesai melakukan pengujian, hapus jaringan virtual dengan:
```bash
sudo clab destroy -t topology.clab.yml
```