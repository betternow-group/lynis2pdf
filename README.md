# Raport Cyberbezpieczeństwa w PDF na podstawie skanowania Lynis.

**Konwertuj raporty audytu [Lynis](https://cisofy.com/lynis/) do przejrzystych, profesjonalnych dokumentów PDF.**

![Build Status](https://github.com/betternow-group/lynis2pdf/actions/workflows/build.yml/badge.svg)
![Latest Release](https://img.shields.io/github/v/release/betternow-group/lynis2pdf)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

`lynis2pdf` to narzędzie napisane w Pythonie, które przetwarza wyniki audytu bezpieczeństwa wygenerowane przez **Lynis** i tworzy estetyczny, gotowy do przekazania dalej raport PDF. Dokument jest wzbogacony o powiązania z **MITRE ATT&CK**, **OWASP Top 10:2025**, rozbudowaną listę zaleceń dotyczących wzmocnienia konfiguracji (hardening) dla każdej kategorii oraz gotowe do skopiowania polecenia diagnostyczne dla każdego ustalenia.

Raporty są przeznaczone do dokumentacji, spełniania wymagań zgodności (compliance), archiwizacji oraz prezentacji wyników Klientom lub kadrze zarządzającej.

## Najważniejsze funkcje

- Struktura **Stan obecny → Wymagania → Sugestie** dla każdej z 6 kategorii tematycznych (uwierzytelnianie, SSH, uprawnienia plików, hardening jądra/systemu, sieć/firewall, logowanie/audyt).
- Powiązania z **MITRE ATT&CK** i **OWASP Top 10:2025** dla każdej kategorii.
- Rozbudowana, stale poszerzana lista zaleceń dot. wzmocnienia konfiguracji oraz gotowe do wklejenia komendy diagnostyczne dla poszczególnych ustaleń Lynis.
- Wskaźnik **Hardening Index** jako wykres kołowy z pełną skalą barw (Critical → Weak → Moderate → Good) i wyraźnie zaznaczoną pozycją aktualnego wyniku na tej skali.
- Wbudowana komenda sprawdzająca dostępność nowszej wersji (`--check-update`).
- Spójna typografia (wbudowany font Open Sans, zaszyty jako base64 bezpośrednio w kodzie skryptu, by nie polegać na tym, czy dana czcionka jest zainstalowana w systemie) niezależna od systemu, na którym uruchamiany jest skrypt.

## Instalacja dla dystrybucji Debian / Ubuntu
### 1. Za pomocą menedżera pakietów apt

Pobierz najnowszy plik `lynis2pdf_<wersja>_amd64.deb` z [zakładki Releases](https://github.com/betternow-group/lynis2pdf/releases), a następnie:

```bash
sudo apt install ./lynis2pdf_*.deb
```

W odróżnieniu od `dpkg -i`, `apt` automatycznie doinstaluje brakujące zależności z repozytoriów - jeżeli są one w jakikolwiek sposób wymagane.

### 2. Za pomocą menedżera pakietów dpkg

Pobierz najnowszy plik `lynis2pdf_<wersja>_amd64.deb` z [zakładki Releases](https://github.com/betternow-group/lynis2pdf/releases), a następnie:

```bash
sudo dpkg -i lynis2pdf_*.deb
```

Instalator konfiguruje polecenie `lynis2pdf` w `/usr/bin`, ikonę pakietu (w `/usr/share/pixmaps` i motywie `hicolor`) oraz wpis `.desktop` wraz z metadanymi AppStream — dzięki temu pakiet jest wyszukiwalny i widoczny (z ikoną i opisem) w graficznych centrach oprogramowania (np. GNOME Software), nie tylko w `dpkg`/`apt`.

#### Aktualizacja

Najprościej: niech `lynis2pdf` sam sprawdzi i zainstaluje nowszą wersję (poprosi o potwierdzenie, patrz sekcja [Bezpieczeństwo -u/--update](#bezpieczeństwo--u---update) poniżej):

```bash
lynis2pdf -u
```

Można też zrobić to ręcznie — pobrać nowy plik `.deb` i uruchomić instalację ponownie; `dpkg` wykrywa, że pakiet jest już zainstalowany, i podmienia pliki w miejscu:

```bash
sudo dpkg -i lynis2pdf_<nowa_wersja>_amd64.deb
```

Samo sprawdzenie, czy dostępna jest nowsza wersja, bez instalowania - przy użyciu `-c ` lub `--check-update`:

```bash
lynis2pdf -c
```

#### Odinstalowanie

```bash
sudo dpkg -r lynis2pdf
```

Aby dodatkowo usunąć wszystkie pliki pozostawione przez pakiet (purge):

```bash
sudo dpkg -P lynis2pdf
```

### 3. Za pomocą źródła

```bash
git clone https://github.com/betternow-group/lynis2pdf.git
cd lynis2pdf
pip install -r requirements.txt
python3 lynis2pdf.py -i /var/log/lynis-report.dat
```

## Jak użyć

Narzędzie odczytuje plik `lynis-report.dat` wygenerowany wcześniej przez Lynis (zwykle czytelny tylko dla roota i zbudowany jako zestawienie danych klucz=wartość) i zapisuje raport PDF w katalogu podanym przez `-o` (domyślnie: bieżący katalog). Uruchomienie `lynis2pdf` bez żadnych argumentów pokazuje menu z opcjami — tak samo jak `-h`/`--help`.

```bash
# 1. Uruchom skan Lynis (jeśli jeszcze nie był wykonany)
sudo lynis audit system

# 2. Wygeneruj raport PDF ze standardowej lokalizacji Lynis
sudo lynis2pdf -i /var/log/lynis-report.dat

# Wskazanie innego pliku wynikowego Lynis (akceptowany jest wyłącznie plik *.dat)
lynis2pdf -i /sciezka/do/lynis-report.dat

# Wskazanie katalogu docelowego dla raportu PDF - tylko katalog, bez nazwy
# pliku; nazwa PDF-a (z data) generowana jest automatycznie
lynis2pdf -i /var/log/lynis-report.dat -o /sciezka/do/katalogu

# Wersja skryptu
lynis2pdf --version

# Sprawdzenie dostępności nowszej wersji (rownowazne: -c oraz --check-update)
lynis2pdf -c

# Pobranie i instalacja najnowszej wersji przez dpkg - prosi o potwierdzenie,
# wymaga roota (sam wywola sudo, jesli nie jestes juz rootem)
lynis2pdf -u

# Menu z pełną listą opcji (tak samo jak uruchomienie bez argumentów)
lynis2pdf --help
```

### Bezpieczeństwo `-u`/`--update`

Zanim `-u` zainstaluje cokolwiek, zawsze pyta o potwierdzenie i pokazuje dokładnie, co zostanie pobrane. Dodatkowo:
- pobiera wyłącznie przez HTTPS, wyłącznie z `github.com` / `*.githubusercontent.com`,
- akceptuje wyłącznie plik o nazwie dokładnie pasującej do wzorca `lynis2pdf_<wersja>_amd64.deb` (nic innego z wydania nie zostanie zainstalowane),
- pobiera do prywatnego katalogu tymczasowego (uprawnienia 0700/0600), usuwanego niezależnie od wyniku,
- porównuje rozmiar pobranego pliku z rozmiarem zgłoszonym przez GitHub - przy niezgodności przerywa przed instalacją,
- uruchamia `dpkg` bez powłoki (brak `shell=True`), więc nazwa pliku nie może zostać zinterpretowana jako dodatkowe polecenie.


## Przyszłość

Repozytorium zostanie wyposażone w klucz GPG, a same paczki będą podpisywane.

**Znane ograniczenie:** `dpkg -i` na pobranym pliku nie weryfikuje podpisu GPG opiekuna pakietu (to zabezpieczenie istnieje dla podpisanych repozytoriów APT, nie dla bezpośrednio pobranego pliku `.deb`). Integralność transferu obecnie opiera się na HTTPS i bezpieczeństwie samego GitHuba, a nie na niezależnym dowodzie kryptograficznym. To typowe ograniczenie tego wzorca (pobierz `.deb` i zainstaluj), nie błąd konkretnej implementacji.

## Opiekun projektu

**Kamil Ciaś** — [kamil.cias@betternow.group](mailto:kamil.cias@betternow.group) — [betternow.group](https://betternow.group)

Od ponad dwóch dekad zajmuje się administracją systemami Linux/UNIX oraz bezpieczeństwem informacji, łącząc perspektywę techniczną, ofensywną i strategiczną. Swoją wiedzę zgłębiał studiując na Politechnice Szczecińskiej, a unikalne doświadczenie operacyjne zdobywał m.in. w sektorze bankowym - pracując dla Santander Bank Polska i Banku mBank - oraz w wymagających strukturach wojskowego lotnictwa taktycznego.

Jako współzałożyciel i CISO w betternow.group odpowiada za budowę oraz utrzymanie systemów zarządzania bezpieczeństwem u Klientów. Specjalizuje się w tworzeniu od podstaw i rozwijaniu działów operacji bezpieczeństwa (SOC), łącząc nowoczesne technologie i procedury z realnymi potrzebami biznesu.