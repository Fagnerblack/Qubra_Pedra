#!/usr/bin/env python3
# coding: utf-8
"""
cracker_with_wordlist.py
Combinações 1..3 palavras (separadores, sufixos, leet limitado), streaming, progresso,
multiprocess, e gravação de TODAS as tentativas em WordList_<timestamp>.txt + WordList.txt.

Uso (exemplo):
 python cracker_with_wordlist.py -d password.txt -H 1f9b839c015becb0568176ca051dc434 --try-all-algos --try-encodings -w 6 --stream --save-attempts
"""

from __future__ import annotations
import argparse
import hashlib
import itertools
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Tuple, Optional, Dict, Set

# -Configuração do paramentro que mais te agrada-
DEFAULT_ENCODING = "utf-8"
LEARN_FILE = "learned_patterns.json"
COMMON_SEPARATORS = ["", "@", "#", "!", ".", "-", "_"]
COMMON_SUFFIXES = ["", "1970", "1971", "1972", "1973", "1974", "1975", "1976", "1977", "1978", "1979", "1980", "1981", "1982", "1983", "1984", "1985", "1986", "1987", "1988", "1989", "1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999", "2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", 
"@1970", "@1971", "@1972", "@1973", "@1974", "@1975", "@1976", "@1977", "@1978", "@1979", "@1980", "@1981", "@1982", "@1983", "@1984", "@1985", "@1986", "@1987", "@1988", "@1989", "@1990", "@1991", "@1992", "@1993", "@1994", "@1995", "@1996", "@1997", "@1998", "@1999", "@2000", "@2001", "@2002", "@2003", "@2004", "@2005", "@2006", "@2007", "@2008", "@2009", "@2010", "@2011", "@2012", "@2013", "@2014", "@2015", "@2016", "@2017", "@2018", "@2019", "@2020", "@2021", "@2022", "@2023", "@2024", "@2025", "@2026", 
"#1970", "#1971", "#1972", "#1973", "#1974", "#1975", "#1976", "#1977", "#1978", "#1979", "#1980", "#1981", "#1982", "#1983", "#1984", "#1985", "#1986", "#1987", "#1988", "#1989", "#1990", "#1991", "#1992", "#1993", "#1994", "#1995", "#1996", "#1997", "#1998", "#1999", "#2000", "#2001", "#2002", "#2003", "#2004", "#2005", "#2006", "#2007", "#2008", "#2009", "#2010", "#2011", "#2012", "#2013", "#2014", "#2015", "#2016", "#2017", "#2018", "#2019", "#2020", "#2021", "#2022", "#2023", "#2024", "#2025", "#2026", 
"!1970", "!1971", "!1972", "!1973", "!1974", "!1975", "!1976", "!1977", "!1978", "!1979", "!1980", "!1981", "!1982", "!1983", "!1984", "!1985", "!1986", "!1987", "!1988", "!1989", "!1990", "!1991", "!1992", "!1993", "!1994", "!1995", "!1996", "!1997", "!1998", "!1999", "!2000", "!2001", "!2002", "!2003", "!2004", "!2005", "!2006", "!2007", "!2008", "!2009", "!2010", "!2011", "!2012", "!2013", "!2014", "!2015", "!2016", "!2017", "!2018", "!2019", "!2020", "!2021", "!2022", "!2023", "!2024", "!2025", "!2026", 
".1970", ".1971", ".1972", ".1973", ".1974", ".1975", ".1976", ".1977", ".1978", ".1979", ".1980", ".1981", ".1982", ".1983", ".1984", ".1985", ".1986", ".1987", ".1988", ".1989", ".1990", ".1991", ".1992", ".1993", ".1994", ".1995", ".1996", ".1997", ".1998", ".1999", ".2000", ".2001", ".2002", ".2003", ".2004", ".2005", ".2006", ".2007", ".2008", ".2009", ".2010", ".2011", ".2012", ".2013", ".2014", ".2015", ".2016", ".2017", ".2018", ".2019", ".2020", ".2021", ".2022", ".2023", ".2024", ".2025", ".2026", 
"-1970", "-1971", "-1972", "-1973", "-1974", "-1975", "-1976", "-1977", "-1978", "-1979", "-1980", "-1981", "-1982", "-1983", "-1984", "-1985", "-1986", "-1987", "-1988", "-1989", "-1990", "-1991", "-1992", "-1993", "-1994", "-1995", "-1996", "-1997", "-1998", "-1999", "-2000", "-2001", "-2002", "-2003", "-2004", "-2005", "-2006", "-2007", "-2008", "-2009", "-2010", "-2011", "-2012", "-2013", "-2014", "-2015", "-2016", "-2017", "-2018", "-2019", "-2020", "-2021", "-2022", "-2023", "-2024", "-2025", "-2026", 
"_1970", "_1971", "_1972", "_1973", "_1974", "_1975", "_1976", "_1977", "_1978", "_1979", "_1980", "_1981", "_1982", "_1983", "_1984", "_1985", "_1986", "_1987", "_1988", "_1989", "_1990", "_1991", "_1992", "_1993", "_1994", "_1995", "_1996", "_1997", "_1998", "_1999", "_2000", "_2001", "_2002", "_2003", "_2004", "_2005", "_2006", "_2007", "_2008", "_2009", "_2010", "_2011", "_2012", "_2013", "_2014", "_2015", "_2016", "_2017", "_2018", "_2019", "_2020", "_2021", "_2022", "_2023", "_2024", "_2025", "_2026"]
MAX_LEET_COMBOS = 256
MAX_CANDIDATES = 50_000_000
BATCH_BASES = 10000

DEFAULT_LEET_MAP = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
}

# Colors
CSI = "\x1b["
RESET = CSI + "0m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"

# ---------------- hash helpers ----------------
def detect_hash_type(h: str) -> str:
    hh = h.strip().lower()
    if len(hh) == 32 and all(c in "0123456789abcdef" for c in hh):
        return "md5"
    if len(hh) == 40 and all(c in "0123456789abcdef" for c in hh):
        return "sha1"
    if len(hh) == 64 and all(c in "0123456789abcdef" for c in hh):
        return "sha256"
    return "unknown"

def hash_of_bytes(alg: str, b: bytes) -> str:
    if alg == "md5":
        return hashlib.md5(b).hexdigest()
    if alg == "sha1":
        return hashlib.sha1(b).hexdigest()
    if alg == "sha256":
        return hashlib.sha256(b).hexdigest()
    raise ValueError("Algoritmo desconhecido")

# ---------------- generation helpers ----------------
def leet_variants(word: str, leet_map: Dict = DEFAULT_LEET_MAP, max_combos: int = MAX_LEET_COMBOS) -> Set[str]:
    pools = []
    for ch in word:
        key = ch.lower()
        if key in leet_map:
            opts = [ch] + leet_map[key]
        else:
            opts = [ch]
        pools.append(opts)
    combos = set()
    prod = itertools.product(*pools)
    for i, tup in enumerate(prod):
        combos.add("".join(tup))
        if i+1 >= max_combos:
            break
    return combos

def capitalize_variants(text: str) -> List[str]:
    return list({text, text.lower(), text.upper(), text.capitalize(), text.title()})

def gen_candidates_from_sequence(seq_words: Tuple[str, ...],
                                 separators: List[str],
                                 suffixes: List[str],
                                 leet_map: Dict,
                                 max_leet_per_word: int) -> Iterable[str]:
    n = len(seq_words)
    if n == 1:
        sep_combinations = [()]
    else:
        sep_combinations = list(itertools.product(separators, repeat=n-1))

    for sep_tuple in sep_combinations:
        per_word_variants = []
        for w in seq_words:
            lv = leet_variants(w, leet_map, max_leet_per_word)
            word_variants = set()
            for v in lv:
                for cap in capitalize_variants(v):
                    word_variants.add(cap)
            per_word_variants.append(list(word_variants))

        for prod_words in itertools.product(*per_word_variants):
            if n == 1:
                base = prod_words[0]
            else:
                pieces = []
                for i, pw in enumerate(prod_words):
                    pieces.append(pw)
                    if i < n-1:
                        pieces.append(sep_tuple[i])
                base = "".join(pieces)
            for suf in suffixes:
                yield base + suf

# ---------------- worker ----------------
def worker_try(candidate: str,
               target_hash: str,
               algos: List[str],
               encodings: List[str]) -> Tuple[bool, str, Optional[str], Optional[str]]:
    for enc in encodings:
        try:
            b = candidate.encode(enc, errors="replace")
        except Exception:
            continue
        for alg in algos:
            if hash_of_bytes(alg, b) == target_hash:
                return True, candidate, alg, enc
    return False, candidate, None, None

# ---------------- progress / printing ----------------
def print_progress_bar(processed: int, total: int, prefix: str = "Progresso", length: int = 40, current_seq: str = ""):
    if total <= 0:
        return
    pct = (processed / total) * 100
    filled = int(length * processed // total)
    bar = "█" * filled + "-" * (length - filled)
    sys.stdout.write(f"\r{prefix} |{bar}| {pct:6.2f}%  Sequência: {current_seq[:30]:30s}")
    sys.stdout.flush()
    if processed >= total:
        print()

# ---------------- learning ----------------
def load_learned(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"suffix_counts": {}, "cracked": []}

def save_learned(state: Dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

# ---------------- orchestrator ----------------
@dataclass
class Config:
    dict_path: str
    target_hash: str
    algorithm: str
    try_all_algos: bool
    try_encodings: bool
    encodings: List[str]
    workers: int
    max_words_in_seq: int
    separators: List[str]
    suffixes: List[str]
    leet_map: Dict
    max_leet_per_word: int
    stream_attempts: bool
    batch_bases: int
    max_candidates: int
    verbose: bool
    learn_file: str
    result_file: Optional[str]
    save_attempts: bool
    attempts_filename: str

def run(cfg: Config):
    if not os.path.exists(cfg.dict_path):
        raise FileNotFoundError("Dicionário não encontrado: " + cfg.dict_path)

    target = cfg.target_hash.strip().lower()
    algorithm = cfg.algorithm
    if cfg.algorithm == "auto":
        detected = detect_hash_type(target)
        if detected == "unknown" and not cfg.try_all_algos:
            raise ValueError("Não foi possível detectar o algoritmo automaticamente. Use --try-all-algos.")
        algorithm = detected

    algos_to_try = ["md5","sha1","sha256"] if cfg.try_all_algos else [algorithm]
    encs = cfg.encodings if cfg.try_encodings else [cfg.encodings[0]]

    # load bases
    with open(cfg.dict_path, "r", encoding=DEFAULT_ENCODING, errors="ignore") as f:
        bases = [ln.strip() for ln in f if ln.strip()]
    if not bases:
        raise ValueError("Dicionário vazio.")

    # learning (for suffix priority)
    state = load_learned(cfg.learn_file)
    suffixes = sorted(cfg.suffixes[:], key=lambda s: -state.get("suffix_counts", {}).get(s, 0))

    n_words = len(bases)
    max_k = min(cfg.max_words_in_seq, n_words)

    # total sequences (permutations) for progress
    total_bases = 0
    for k in range(1, max_k+1):
        perm = 1
        for i in range(n_words, n_words - k, -1):
            perm *= i
        total_bases += perm
    if total_bases == 0:
        raise ValueError("Sem sequências para gerar (dicionário muito pequeno para max_words_in_seq).")

    processed_bases = 0
    attempted_candidates = 0
    found = False
    found_password = None
    found_algo = None
    found_enc = None

    start = time.time()

    # prepare attempts file if needed
    attempts_fh = None
    if cfg.save_attempts:
        attempts_fh = open(cfg.attempts_filename, "w", encoding="utf-8", buffering=1)  # line buffered
        # header
        attempts_fh.write(f"# Attempts generated {datetime.now().isoformat()}\n")

    with ProcessPoolExecutor(max_workers=cfg.workers) as executor:
        # iterate k=1..max_k
        for k in range(1, max_k+1):
            for perm in itertools.permutations(bases, k):
                # generate a reasonable batch for this perm
                candidate_gen = gen_candidates_from_sequence(perm, cfg.separators, suffixes, cfg.leet_map, cfg.max_leet_per_word)
                batch_candidates = []
                for c in candidate_gen:
                    batch_candidates.append(c)
                    if len(batch_candidates) >= cfg.batch_bases * 5:  # safety batch
                        break
                if not batch_candidates:
                    processed_bases += 1
                    print_progress_bar(processed_bases, total_bases, current_seq=" ".join(perm))
                    continue

                attempted_candidates += len(batch_candidates)
                if attempted_candidates > cfg.max_candidates:
                    print(color("[WARN] limite de candidatos excedido. Abortando.", YELLOW))
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                future_map = {executor.submit(worker_try, cand, target, algos_to_try, encs): cand for cand in batch_candidates}

                for fut in as_completed(future_map):
                    ok, cand, algo_used, enc_used = fut.result()
                    # write attempt to file
                    if cfg.save_attempts and attempts_fh:
                        try:
                            attempts_fh.write(cand + "\n")
                        except Exception:
                            pass
                    # streaming display
                    if cfg.stream_attempts:
                        cand_disp = cand if len(cand) <= 60 else cand[:57] + "..."
                        if ok:
                            print(color(f"TRY  {cand_disp:60s} => MATCH (alg={algo_used} enc={enc_used})", GREEN))
                        else:
                            print(f"TRY  {cand_disp}")
                    if cfg.verbose and attempted_candidates <= 200:
                        print(f"[DEBUG] tested {cand!r} -> alg={algo_used} enc={enc_used}", file=sys.stderr)
                    if ok:
                        found = True
                        found_password = cand
                        found_algo = algo_used
                        found_enc = enc_used
                        # cancel remaining futures
                        for f in future_map:
                            if not f.done():
                                f.cancel()
                        break

                processed_bases += 1
                print_progress_bar(processed_bases, total_bases, current_seq=" ".join(perm))

                if found:
                    break
            if attempted_candidates > cfg.max_candidates or found:
                break

    elapsed = time.time() - start

    # finalize attempts file and create WordList.txt copy
    if attempts_fh:
        attempts_fh.flush()
        attempts_fh.close()
        # copy to WordList.txt (overwrite)
        try:
            with open(cfg.attempts_filename, "r", encoding="utf-8") as src, open("WordList.txt", "w", encoding="utf-8") as dst:
                for line in src:
                    dst.write(line)
        except Exception:
            pass

    # learning update
    if found and found_password:
        import re
        m = re.search(r'(\d{1,6})$', found_password)
        if m:
            suf = m.group(1)
            state.setdefault("suffix_counts", {})
            state["suffix_counts"][suf] = state["suffix_counts"].get(suf, 0) + 1
        state.setdefault("cracked", [])
        state["cracked"].append({"password": found_password, "time": time.time()})
        save_learned(state, cfg.learn_file)

    # save result file optional
    if cfg.result_file:
        try:
            with open(cfg.result_file, "w", encoding="utf-8") as rf:
                if found:
                    rf.write(f"FOUND\nhash={cfg.target_hash}\npassword={found_password}\nalgorithm={found_algo}\nencoding={found_enc}\ntries={attempted_candidates}\nelapsed={elapsed:.3f}\n")
                else:
                    rf.write(f"NOT_FOUND\nhash={cfg.target_hash}\ntries={attempted_candidates}\nelapsed={elapsed:.3f}\n")
        except Exception:
            pass

    return {
        "found": found,
        "password": found_password,
        "algorithm": found_algo,
        "encoding": found_enc,
        "tries": attempted_candidates,
        "elapsed": elapsed,
        "attempts_file": cfg.attempts_filename if cfg.save_attempts else None
    }

# ---------------- CLI ----------------
def build_cli():
    p = argparse.ArgumentParser(description="Cracker combinacional com gravação de todas tentativas (WordList).")
    p.add_argument("-d","--dict", required=True, help="Arquivo com palavras-base (uma por linha).")
    p.add_argument("-H","--hash", required=True, help="Hash alvo (hex).")
    p.add_argument("-a","--algorithm", choices=["auto","md5","sha1","sha256"], default="auto", help="Algoritmo (auto detecta por tamanho).")
    p.add_argument("--try-all-algos", action="store_true", help="Tenta md5+sha1+sha256 por candidato.")
    p.add_argument("--try-encodings", action="store_true", help="Testa encodings utf-8, latin-1, utf-16le, utf-16be.")
    p.add_argument("-w","--workers", type=int, default=max(1, (os.cpu_count() or 2)), help="Número de processos.")
    p.add_argument("--max-words-in-seq", type=int, default=3, choices=[1,2,3], help="Máximo de palavras na sequência (1..3).")
    p.add_argument("--separators", default=",".join(COMMON_SEPARATORS), help="Separadores (comma-separated).")
    p.add_argument("--suffixes", default=",".join(COMMON_SUFFIXES), help="Sufixos (comma-separated).")
    p.add_argument("--max-leet-per-word", type=int, default=MAX_LEET_COMBOS, help="Limite de variações leet por palavra.")
    p.add_argument("--stream", action="store_true", default=True, help="Stream de tentativas (default ON).")
    p.add_argument("--no-stream", dest="no_stream", action="store_true", help="Desativa stream de tentativas.")
    p.add_argument("--batch-bases", type=int, default=BATCH_BASES, help="Quantas candidatos por permuta (controle de memória).")
    p.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES, help="Limite de candidatos gerados por segurança.")
    p.add_argument("--verbose","-v", action="store_true", help="Modo verboso (debug).")
    p.add_argument("--learn-file", default=LEARN_FILE, help="Arquivo para persistência do aprendizado.")
    p.add_argument("--result-file", default=None, help="Salvar resultado em arquivo.")
    p.add_argument("--save-attempts", action="store_true", default=True, help="Salvar todas as tentativas em WordList_<timestamp>.txt (default ON).")
    return p

def main(argv=None):
    p = build_cli()
    args = p.parse_args(argv)

    encodings = ["utf-8", "latin-1", "utf-16le", "utf-16be"]
    seps = args.separators.split(",") if args.separators else COMMON_SEPARATORS
    sufs = args.suffixes.split(",") if args.suffixes else COMMON_SUFFIXES

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    attempts_filename = f"WordList_{timestamp}.txt"

    cfg = Config(
        dict_path=args.dict,
        target_hash=args.hash.strip().lower(),
        algorithm=args.algorithm,
        try_all_algos=args.try_all_algos,
        try_encodings=args.try_encodings,
        encodings=encodings,
        workers=args.workers,
        max_words_in_seq=args.max_words_in_seq,
        separators=seps,
        suffixes=sufs,
        leet_map=DEFAULT_LEET_MAP,
        max_leet_per_word=args.max_leet_per_word,
        stream_attempts=not args.no_stream,
        batch_bases=args.batch_bases,
        max_candidates=args.max_candidates,
        verbose=args.verbose,
        learn_file=args.learn_file,
        result_file=args.result_file,
        save_attempts=args.save_attempts,
        attempts_filename=attempts_filename
    )

    print("\n" + "="*60)
    print(f" Iniciando cracker combinacional | algorithm={cfg.algorithm} | workers={cfg.workers} | max_seq_words={cfg.max_words_in_seq}")
    print(" Tentativas serão salvas em:", attempts_filename if cfg.save_attempts else "Desativado")
    print("="*60)
    try:
        res = run(cfg)
    except Exception as e:
        print(color("Erro: " + str(e), RED), file=sys.stderr)
        sys.exit(1)

    if res["found"]:
        print(color("\n✅ SENHA ENCONTRADA!", GREEN))
        print(f"🔓 Hash alvo: {cfg.target_hash}")
        print(f"🔑 Senha : {color(res['password'], CYAN)}")
        print(f"Algoritmo detectado/usado: {res['algorithm']} | Encoding: {res['encoding']}")
    else:
        print(color("\n❌ Senha NÃO encontrada.", RED))
    print(f"⚡ Tentativas (aprox.): {res['tries']:,} | Tempo: {res['elapsed']:.2f}s")
    if res.get("attempts_file"):
        print("Arquivo de tentativas:", res["attempts_file"])
        print("Cópia atualizada: WordList.txt")
    if cfg.result_file:
        print("Resultado salvo em:", cfg.result_file)
    print("Estado de aprendizado salvo em:", cfg.learn_file)

if __name__ == "__main__":
    main()
