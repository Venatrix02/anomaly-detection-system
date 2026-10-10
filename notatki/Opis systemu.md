# Opis systemu

**Temat pracy:** System wykrywania anomalii w ruchu sieciowym z wykorzystaniem metod uczenia maszynowego

**Język programowania:** Python.

## **Ogólna koncepcja:**

* Prezentowanie wyników na panelu webowym.
* Zbieranie danych o ruchu sieciowym.
* Nauka "normalnego" zachowania sieci.
* Analiza zebranych danych.
* Wykrywanie odchyleń od normy.

## **a) Moduł 1 - zbieranie danych:**

* Program obserwuje ruch sieciowy w czasie rzeczywistym lub z danych historycznych.
* Zapisuje podstawowe informacje o pakietach: adres IP nadawcy i odbiorcy, port, protokół, rozmiar pakietu, flagi TCP.
* Nie analizuje treści pakietów (payloadu), tylko nagłówki.
* Dane są dzielone na krótkie przedziały czasowe, np. co 10 sekund.
* Przechwycone dane są przesyłane do modułu tworzenia cech.
* Interfejs sieciowy jest konfigurowany przez zmienną środowiskową `SNIFFER_IFACE` w pliku `.env`, co umożliwia łatwe przenoszenie systemu na inne maszyny bez zmiany kodu.
* System obsługuje bezpieczne zamykanie (sygnały SIGINT/SIGTERM), co zapobiega utracie danych i zawieszeniu interfejsu sieciowego przy zatrzymaniu programu (np. Ctrl+C).
* **Narzędzia:** Python i Scapy.

## **b) Moduł 2 - tworzenie cech:**

* Surowe pakiety są zamieniane w liczby, które opisują ruch sieciowy w danym czasie.
* Tworzy się tzw. wektor cech składający się z 15 elementów:
  1. `packets_count` - liczba pakietów w oknie czasowym
  2. `unique_ips` - liczba unikalnych adresów IP
  3. `unique_ports` - liczba unikalnych portów
  4. `avg_packet_size` - średni rozmiar pakietu
  5. `tcp_ratio` - udział pakietów TCP
  6. `udp_ratio` - udział pakietów UDP
  7. `other_ratio` - udział pakietów innych protokołów
  8. `unique_connections` - liczba unikalnych połączeń
  9. `dominant_port` - najczęściej występujący port docelowy
  10. `synchronization_packets_count` - liczba pakietów SYN
  11. `acknowledgment_packets_count` - liczba pakietów ACK
  12. `reset_packets_count` - liczba pakietów RST
  13. `finish_packets_count` - liczba pakietów FIN
  14. `packet_size_std` - odchylenie standardowe rozmiaru pakietu (ataki flood mają pakiety o stałym rozmiarze, co obniża tę wartość)
  15. `syn_to_ack_ratio` - stosunek SYN do ACK (wykrywanie SYN Flood i skanowania portów - wysoka wartość oznacza dużo SYN bez ACK)
* Wartości są agregowane w przedziałach czasowych, aby model miał stałą liczbę cech.
* Wektory cech są przesyłane do modułu uczenia modelu.
* Wykorzystywana jest technika sliding window.
* **Narzędzia:** Python, Pandas i NumPy.

## **c) Moduł 3 - uczenie modelu:**

* System uczy się, jak wygląda normalny ruch sieciowy, korzystając z danych historycznych zapisanych w bazie danych (tabela `network_metrics`).
* Tworzy matematyczny model zachowania sieci, który pozwala wykrywać anomalie.
* Przed treningiem dane są czyszczone: odrzucane są rekordy ze skrajnymi wartościami (np. `packets_count` > 100000, co może być błędem sniffera), a brakujące wartości są uzupełniane zerami.
* System trenuje równolegle trzy różne algorytmy, umożliwiając późniejsze porównanie ich skuteczności:
  * *Isolation Forest* – model izoluje anomalie, ponieważ różnią się one od większości danych.
  * *One-Class SVM* – model uczy się granicy obejmującej większość normalnych danych; wszystko poza nią uznawane jest za anomalię.
  * *Metoda progowa* – jeśli wartość cechy wychodzi poza ustalony przedział średnia ± odchylenie standardowe, uznaje się ją za anomalię.
* Dane treningowe mogą być zbierane automatycznie przez wbudowany generator ruchu sieciowego (oparty na bibliotece Selenium), który symuluje zachowanie użytkownika przeglądającego internet. Generator wykorzystuje wbudowany Selenium Manager do automatycznego pobierania odpowiedniego sterownika Chrome.
* Wytrenowane modele są zapisywane do plików w formacie pickle (folder `models/`), a informacje o nich (nazwa, typ algorytmu, data treningu, parametry, flaga aktywności) są rejestrowane w tabeli `model_info` w bazie danych.
* Dodatkowo metadane modelu (data treningu, liczba próbek, lista cech) są zapisywane do pliku `model_metadata.json`, co ułatwia audyt i debugowanie.
* Dzięki temu system umożliwia przełączanie aktywnego modelu wykrywającego anomalie bez konieczności ponownego trenowania.
* Model trenuje się na danych normalnych, a następnie testuje na nowych danych, aby sprawdzić skuteczność.
* Po wytrenowaniu model jest gotowy do analizowania nowych danych w czasie rzeczywistym.
* **Narzędzia:** Python, Scikit-Learn, Pandas, NumPy, joblib, Selenium.

## **d) Moduł 4 - wykrywanie anomalii:**

* Nowe dane ruchu sieciowego są przetwarzane i porównywane z aktualnie aktywnym modelem (wczytywanym z bazy danych na podstawie flagi `is_active` w tabeli `model_info`).
* System oblicza `anomaly_score`, czyli miarę odchylenia od normy.
* Jeśli wynik przekracza ustalony próg, zdarzenie klasyfikuje się jako anomalia.
* Wykryte anomalie są przekazywane do modułu alertów.
* Ten moduł działa w czasie rzeczywistym i stale monitoruje sieć.
* Dane wejściowe są przekazywane do modelu w formie DataFrame z nazwami kolumn, co zapewnia zgodność z formatem danych treningowych i eliminuje ostrzeżenia biblioteki scikit-learn.
* **Narzędzia:** Python i Scikit-Learn.

## **e) Moduł 5 - system alertów:**

* Każda wykryta anomalia jest rejestrowana i przypisywany jest jej poziom istotności (`low`, `medium`, `high`).
* Poziom istotności jest wyznaczany na podstawie `anomaly_score` według ustalonych progów:
  * `score < -0.5` → `high`
  * `score < -0.2` → `medium`
  * `score >= -0.2` → `low`
* Alerty są zapisywane w bazie danych (tabela `alerts`) i mogą być wyświetlane administratorowi.
* System stosuje mechanizm **cooldown alertów**: zamiast tworzyć nowy alert dla każdej wykrytej anomalii, system sprawdza, czy w ciągu ostatnich 5 minut istnieje już alert o tym samym poziomie istotności (`severity_level`). Jeśli tak - aktualizuje czas ostatniego wystąpienia (`last_seen`), zamiast tworzyć duplikat. Dzięki temu administrator nie jest zalewany setkami identycznych powiadomień podczas trwającego ataku.
* Historia alertów pozwala na analizę trendów i raportowanie bezpieczeństwa sieci.
* Alerty mogą być filtrowane i sortowane w panelu administratora.
* **Narzędzia:** Python i baza danych (MariaDB).


## **f) Moduł 6 - baza danych:**

* Baza przechowuje metryki ruchu sieciowego, wyniki modelu ML, `anomaly_score` i historię alertów.
* Zapewnia szybki dostęp do danych i możliwość wyszukiwania lub filtrowania.
* Pozwala na generowanie raportów okresowych i analizę trendów (system generuje raporty i analizuje trendy poprzez agregowanie metryk i alertów w wybranych okresach czasu oraz prezentowanie średnich, sum i odchyleń w formie wykresów pokazujących zmiany w zachowaniu sieci).
* Umożliwia zapis logów systemowych (np. błędów lub restartów systemu).
* Integruje się z panelem administratora, aby wizualizować dane w czasie rzeczywistym.
* Dane są zapisywane w sposób uporządkowany w tabelach relacyjnych.
* Wszystkie operacje na bazie danych wykorzystują context managery SQLAlchemy (`with SessionLocal() as session:`), co zapewnia automatyczne i bezpieczne zamykanie sesji nawet w przypadku wystąpienia błędów.
* Kluczowe kolumny (timestamp, status, severity_level, is_active) posiadają indeksy przyspieszające zapytania, co jest istotne szczególnie dla panelu administratora.
* **Narzędzia:** MariaDB i Python (ORM: SQLAlchemy, sterownik: PyMySQL).

## **g) Moduł 7 - panel administratora:**

* Wyświetla `anomaly_score` w czasie rzeczywistym i listę wykrytych alertów.
* Panel pokazuje status sieci (OK lub zagrożenie) i wizualizuje ruch sieciowy w formie wykresów.
* Dostęp do panelu administratora jest chroniony logowaniem, które wymaga podania poprawnych danych użytkownika zapisanych w bazie systemu.
* Umożliwia przegląd historii zdarzeń i raportów.
* Panel administratora zawiera zakładki umożliwiające przeglądanie bieżącego stanu sieci, listy wykrytych alertów, historii anomalii oraz generowania raportów i analizy trendów.
* Pozwala filtrować i sortować alerty według czasu, typu i poziomu istotności.
* Panel umożliwia eksport danych do plików CSV lub PDF.
* **Narzędzia:** Python i Django lub FastAPI i Chart.js do wykresów.

## **h) Moduł 8 (dodatkowy) - analiza porównawcza i generowanie wizualizacji do artykułu:**

System został wyposażony w dedykowany moduł analityczny (`generate_paper_figures.py`), który pobiera dane z bazy i generuje profesjonalne wizualizacje oraz statystyki niezbędne do oceny skuteczności modeli. Moduł ten realizuje:
- Normalizację osi czasu w celu porównywalności wykresów dla różnych modeli (każdy model był testowany w oddzielnej sesji w celu zachowania czystego stanu detekcji).
- Generowanie wykresów liniowych (subplots) pokazujących ewolucję `anomaly_score` w czasie, z wizualnym oznaczeniem momentu rozpoczęcia ataku (czerwona przerywana linia).
- Tworzenie wykresów skrzynkowych (boxplot) porównujących rozkład wyników między Isolation Forest a One-Class SVM oraz osobno dla Metody Progowej.
- Eksport surowych danych i tabel statystycznych (średnia, odchylenie standardowe, min, max, liczba próbek) do formatu CSV.
Dzięki temu modułowi praca zawiera twarde dane empiryczne potwierdzające, że:
  - Isolation Forest oferuje najbardziej stabilne wykrywanie (średni score ok. -0.686, odchylenie standardowe 0.009, 106 wykrytych anomalii).
  - One-Class SVM charakteryzuje się bardziej zachowawczą reakcją (51 wykrytych anomalii, szerszy rozrzut wyników).
  - Metoda Progowa jest wysoce agresywna i czuła na pojedyncze piki metryk (14 wykrytych anomalii, skrajne wartości score sięgające -542.5).
Dodatkowo zweryfikowano skuteczność mechanizmu cooldown, który zredukował liczbę generowanych alertów o ponad 99% (z 106 pojedynczych detekcji do 1 skonsolidowanego alertu z aktualizowanym czasem `last_seen`).

## **Ogólne zabezpieczenia systemu:**

* System stosuje szyfrowane połączenia (HTTPS/SSL) między frontendem a backendem, aby chronić dane przesyłane w sieci.
* Wprowadzenie ograniczenia liczby prób logowania - po kilku nieudanych próbach konto może być tymczasowo zablokowane.
* Wszystkie dane wprowadzane przez użytkownika są walidowane, aby zapobiegać atakom typu SQL Injection lub XSS.
* System grupuje podobne alerty w jedno zdarzenie (mechanizm cooldown), ograniczając nadmiar powiadomień i ułatwiając pracę administratora.
* Uprawnienia są ograniczone do administratorów, brak ról dla zwykłych użytkowników, co zmniejsza ryzyko nieautoryzowanego dostępu.
* Panel administratora jest chroniony logowaniem - dostęp mają tylko użytkownicy zarejestrowani w systemie.
* Hasła użytkowników są przechowywane w postaci hash, co uniemożliwia ich odczyt w bazie danych.

## **Dodatkowe uwagi o systemie:**

* Możliwość wizualizacji danych w panelu administratora ułatwia szybkie reagowanie na zagrożenia i przegląd stanu sieci.
* System jest modularny - składa się z części odpowiedzialnej za zbieranie danych, wykrywanie anomalii, generowanie alertów i raportów, co ułatwia rozwój i konserwację.
* System obsługuje dane historyczne, co pozwala analizować trendy w ruchu sieciowym oraz skuteczność wykrywania anomalii.
* System przewiduje możliwość rozszerzenia funkcjonalności - np. dodanie nowych typów alertów, dodatkowych metryk sieciowych lub nowych modeli ML.
* Zastosowanie relacyjnej bazy danych umożliwia spójne przechowywanie danych i logiczne powiązanie rekordów między modułami.
* Konfiguracja systemu (dane logowania do bazy, interfejs sieciowy) jest przechowywana w pliku `.env`, co ułatwia przenoszenie systemu na inne środowiska.

## **Testowanie systemu:**

* System został przetestowany w warunkach kontrolowanych, z wykorzystaniem narzędzia `nmap` do symulacji ataku typu skanowanie portów (SYN scan). Testy potwierdziły skuteczność wszystkich trzech algorytmów w wykrywaniu anomalii:
  * **Isolation Forest** - stabilne wyniki (ok. `-0.70`), szybka i pewna reakcja od pierwszego okna czasowego.
  * **One-Class SVM** - stopniowa eskalacja pewności (od `-0.15` do `-1.23`), bardziej zachowawczy na początku.
  * **Metoda progowa** - najbardziej agresywna reakcja (skrajne wyniki sięgające `-542.5`), bardzo czuła na nagłe piki pojedynczych metryk.
* Podczas testów z atakiem SYN scan (`nmap -sS -Pn -p 1-10000 8.8.8.8`) system wykrył anomalię z wynikiem `-0.70` i poziomem istotności `high`. Mechanizm cooldown skutecznie ograniczył liczbę alertów - mimo 96+ wykrytych anomalii w trakcie ataku, w bazie danych utworzony został tylko 1 alert z aktualizowanym czasem `last_seen`.