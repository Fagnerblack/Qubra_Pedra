# 🧠 Quebra_Pedra  
Cracker combinacional e gerador de wordlists em Python 3 — criado para pesquisa, estudo e testes **autorizados** de segurança.

> **Autor:** [Fagner Santos Mello Pinheiro](https://www.linkedin.com/in/fagner-santos-470a80269)  
> **GitHub:** [Fagnerblack](https://github.com/Fagnerblack)

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Segurança](https://img.shields.io/badge/uso%20autorizado%20apenas-red.svg)](https://github.com/Fagnerblack/Qubra_Pedra/blob/f3ed12121afe066cb22adc34b5cebf55431b7a22/Security)

---

## ⚠️ Aviso Legal e Ético

> Este projeto é **estritamente para fins educacionais e de auditoria autorizada**.  
> O uso indevido (contra sistemas, contas ou dados sem permissão) é **crime** sob as leis de diversos países.  
>  
> Ao utilizar este software, você **concorda** em:  
> - Usá-lo apenas em ambientes sob sua propriedade ou com permissão explícita.  
> - Não compartilhar wordlists ou resultados fora de contexto autorizado.  
> - Assumir total responsabilidade pelo uso e pelas consequências.  

---

## 🚀 Visão Geral

**Quebra_Pedra** é um *cracker* de aprendizado e auditoria em Python com foco em:
- Quebrar Criptografias de MD5 através de um ataque de força bruta gerando uma WordList com milhares de senhas para outras atividades futuras.
- Geração combinacional de candidatos;
- Variações *leet*, capitalizações e separadores;
- Uso de sufixos como anos e símbolos (`["", "@", "#", "!", ".", "-", "_"]`);
- Processamento paralelo (multiprocess);
- Logs e persistência de aprendizado entre execuções.

Ideal para:
- testes de força bruta controlados;
- análise de dicionários e wordlists;
- estudo de algoritmos de hash (MD5, SHA1, SHA256);
- pesquisa de segurança ofensiva ética (*red teaming autorizado*).

---

## 🧩 Estrutura do Repositório

Quebra_Pedra/
├── cracker_with_wordlist.py # script principal

├── README.md # este arquivo

├── MANUAL.md # manual completo (opcional)

├── CONTRIBUTING.md

├── SECURITY.md

├── DISCLAIMER.md

├── LICENSE

├── tests/

│ ├── dict_test.txt

│ └── run_test.sh

└── wordlists/

└── WordList_<timestamp>.txt
