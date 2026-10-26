# SMF-ASSIST — Trustworthy Enterprise RAG Agent

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?logo=pytorch&logoColor=white)
![Hugging Face Transformers](https://img.shields.io/badge/%F0%9F%A4%97%20Transformers-FFD21E?logoColor=black)
![Sentence Transformers](https://img.shields.io/badge/Embeddings-MiniLM--L6--v2-blue)
![FAISS](https://img.shields.io/badge/Vector%20Store-FAISS-green)
![Gradio](https://img.shields.io/badge/UI-Gradio-F97316?logo=gradio&logoColor=white)
![NIST AI RMF](https://img.shields.io/badge/Framework-NIST%20AI%20RMF-purple)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

Adversarial red-teaming, threat modeling, and defense-in-depth hardening for an enterprise
Retrieval-Augmented Generation (RAG) support assistant. Built around an industrial engagement
with the **Singapore Manufacturing Federation (SMF)**, this repository evaluates how an SME
helpdesk chatbot responds to adversarial prompt injection, internal system-prompt/PII extraction,
and knowledge-base poisoning — and implements a **4-layer security architecture** reducing Attack
Success Rate (ASR) to **0%** across all threat categories without compromising legitimate inquiry quality.

> Retrieval-Augmented Generation (RAG) grounds language models in verified domain knowledge, but it
> also inherits every vulnerability of the retrieval pipeline and generation context. An enterprise
> chatbot cannot simply trust user inputs or retrieved database chunks. Hardening a production RAG
> assistant requires **defense-in-depth**: filtering malicious intent at the perimeter, enforcing strict
> boundary isolation on retrieved context, verifying document provenance cryptographically, and
> scrubbing output streams for leaked tokens and private records before reaching the user.

---

## What it does
- 🛡️ **Adversarial Red-Teaming Benchmark** — comprehensive adversarial evaluation across three
  critical enterprise attack vectors: **Direct/Indirect Prompt Injection**, **System-Prompt & Context
  Extraction**, and **RAG Knowledge-Base Poisoning**.
- 🧱 **4-Layer Defense-in-Depth Pipeline**:
  1. *Layer 1 (Perimeter):* Input regex and semantic intent filter neutralizing jailbreak tokens.
  2. *Layer 2 (Knowledge Base):* Source provenance whitelist and content verification stopping injected
     phishing or rogue fee notices.
  3. *Layer 3 (Model Context):* Structured XML delimiter boundary isolation separating untrusted reference
     data from operational instructions.
  4. *Layer 4 (Egress):* Output scrubber detecting internal canary tokens, ticket identifiers (`ESC-xxxx`),
     and member account numbers (`M-xxxx`).
- 📉 **Empirical Risk Reduction** — drops Attack Success Rate (ASR) from **83% $\rightarrow$ 0%** on
  prompt injection, **67% $\rightarrow$ 0%** on extraction, and **60% $\rightarrow$ 0%** on poisoning.
- 📈 **Preserved & Enhanced Utility** — benign SME question accuracy increases from **80% $\rightarrow$ 90%**
  due to structured prompt formatting, with **zero legitimate member queries falsely blocked**.
- 🖥️ **Interactive Gradio Replay Terminal** — a live, side-by-side comparative dashboard illustrating
  bare RAG vulnerabilities alongside defended mitigations.

## Architecture & 4-Layer Defence
```
User / Attacker Query ──▶ [Layer 1: Input Guardrail]
                                  │ (Passed: non-adversarial)
                                  ▼
                         [Vector Search (FAISS)]
                                  │ (Retrieve top-k chunks)
                                  ▼
                     [Layer 2: Provenance Sanitizer]
                     Filter unverified sources & phishing
                                  │ (Verified chunks only)
                                  ▼
                     [Layer 3: Bounded Context]
                     <context> XML encapsulation + negative constraints
                                  │
                                  ▼
                     [LLM: Qwen2.5 / TinyLlama]
                                  │ (Raw generated response)
                                  ▼
                     [Layer 4: Output Scrubber]
                     PII redaction, canary trap & prompt-leak filter
                                  │
                                  ▼
                        Verified Safe Response
```

## Empirical Attack & Defence Results

Evaluated on `Qwen/Qwen2.5-0.5B-Instruct` and `TinyLlama/TinyLlama-1.1B-Chat-v1.0` with
`sentence-transformers/all-MiniLM-L6-v2` and FAISS:

| Attack Vector | Vulnerability & Scenario | Bare RAG ASR | Defended ASR | Reduction |
| :--- | :--- | :---: | :---: | :---: |
| **Prompt Injection** | Jailbreak instruction override (`FreeBot`, `PWNED`) | **83.3%** | **0.0%** | **-83.3 pp** |
| **Context Extraction** | Internal support canary token & member escalation leak | **66.7%** | **0.0%** | **-66.7 pp** |
| **Corpus Poisoning** | Malicious PayNow fee injected into grant advice | **60.0%** | **0.0%** | **-60.0 pp** |
| **Benign Utility** | Legitimate SME inquiries (EDG, PSG grants, AI events) | **80.0% acc** | **90.0% acc** | **+10.0 pp** |

*(False Positive Rate on legitimate inquiries: **0.0%** across all test suites).*

## Industrial Context (SIT × SMF Project 10)

This case study is grounded in an applied industrial project for the **Singapore Manufacturing
Federation (SMF)** (*Project 10 — SMF Agentic AI for Manufacturing*). SMF represents over 5,000 corporate
members, driving industry transformation and AI adoption across Singapore's manufacturing ecosystem.

> [!NOTE]
> **Synthetic Testbed & Data Confidentiality Notice**  
> To protect enterprise confidentiality and comply with data privacy standards (PDPA), the knowledge
> base (`knowledge_base.json`), internal staff escalation records, and canary tokens used in this
> repository are **curated synthetic data**. They realistically simulate SMF manufacturing advisory
> workflows (e.g., EDG and PSG grant guidelines, AI Solution Day matchmaking) within a controlled,
> lightweight testbed designed specifically for reproducible adversarial red-teaming.

An automated member assistant must handle sensitive workflows:
* Explaining co-funding grant criteria (e.g., Enterprise Development Grant — EDG up to 50%).
* Evaluating ROI previews across productivity and automation initiatives.
* Handling confidential member records without leaking account statuses to unauthorized callers.

### Governance Mapping (NIST AI RMF)
- **MAP Function:** Categorized risks across operational domains: R1 (brand reputation / hijack),
  R2 (confidentiality & PII loss under PDPA), and R3 (financial phishing / fraud).
- **MEASURE Function:** Quantified adversarial risk using Attack Success Rate (ASR) before and after
  guardrail deployment.
- **MANAGE Function:** Established automated tripwires, canary auditing, and fallback escalations
  to human officers for contested queries.

## Run it
Requires **Python 3.10 – 3.12**.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

- **Interactive dashboard:** Launches a local web app on `http://localhost:7862` with pre-loaded attack
  scenarios and side-by-side evaluation tabs.
- **Full experimental notebook:** View complete training, red-teaming sweeps, and defensive implementations
  in [`notebooks/rag_chatbot_trustworthy_ai.ipynb`](notebooks/rag_chatbot_trustworthy_ai.ipynb).
- **Formal case study report:** Full 9-page research report available in [`docs/SMF_Trustworthy_AI_Report.pdf`](docs/SMF_Trustworthy_AI_Report.pdf).

## Project structure
| Path | Role |
|------|------|
| `app.py` | Interactive Gradio attack-replay and live evaluation dashboard |
| `guardrails.py` | Modular 4-layer security pipeline (input filters, context bounds, provenance sanitizer, PII scrubber) |
| `data/` | Knowledge base, attack payloads, benign evaluation suites, and ASR benchmark CSVs |
| `docs/` | Formal 9-page Trustworthy AI project report (`SMF_Trustworthy_AI_Report.pdf`) |
| `notebooks/` | Master attack/defense notebook, Gradio demo notebook, and executed PDF run transcripts |
| `requirements.txt` | Python dependencies |

## Tech
Python · PyTorch · Hugging Face Transformers · Sentence Transformers (`all-MiniLM-L6-v2`) · FAISS · Gradio · Pandas · NumPy

## Limitations & further work
- **Guardrail evasion:** Deterministic regex filters catch known patterns; high-assurance enterprise systems
  should pair rule-based filters with a small, fine-tuned safety classifier (e.g. Llama Guard 3).
- **Multi-turn state tracking:** In multi-turn dialogue, attackers can build up injection payloads across
  multiple conversational turns (crescendo attacks).
- **Dynamic knowledge-base attestation:** In production, corporate vector stores require signed cryptographic
  checksums and role-based access control (RBAC) at the document level.

## License
MIT — see [LICENSE](LICENSE).

