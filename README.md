# HydraMatrix Cipher

Custom symmetric block cipher implementation with interactive web UI.

---

## Requirements

- Python 3.9+
- pip

---

## Installation

**1. Clone repositori**

```bash
git clone https://github.com/username/kamsis_kriptografi.git
cd kamsis_kriptografi
```

**2. virtual environment**

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

---

## Run App

```bash
streamlit run app.py
```
port `http://localhost:8501`

---

## Tests

```bash
python -m pytest tests/ -v
```

---

## project 

```
kamsis_kriptografi/
├── requirements.txt
├── app.py
├── hydra_cipher/
│   ├── core.py
│   ├── key_schedule.py
│   ├── gf_math.py
│   └── utils.py
└── tests/
    ├── test_cipher.py
    ├── test_avalanche.py
    └── test_performance.py
```
