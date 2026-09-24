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
* Zapisuje podstawowe informacje o pakietach: adres IP nadawcy i odbiorcy, port, protokół, rozmiar pakietu.
* Nie analizuje treści pakietów (payloadu), tylko nagłówki.
* Dane są dzielone na krótkie przedziały czasowe, np. co 10 sekund.
* Przechwycone dane są przesyłane do modułu tworzenia cech.
* **Narzędzia:**  Python i Scapy.

## **b) Moduł 2 - tworzenie cech:**

* Surowe pakiety są zamieniane w liczby, które opisują ruch sieciowy w danym czasie.
* Tworzy się tzw. wektor cech, np. liczba pakietów, liczba portów, liczba unikalnych IP, średni rozmiar pakietu, udział TCP/UDP.
* Wartości są agregowane w przedziałach czasowych, aby model miał stałą liczbę cech.
* Wektory cech są przesyłane do modułu uczenia modelu.
* Wykorzystywana jest technika sliding window.
* **Narzędzia:** Python i Pandas.

## **c) Moduł 3 - uczenie modelu:**

* System uczy się, jak wygląda normalny ruch sieciowy, korzystając z danych historycznych zapisanych w bazie danych (tabela `network_metrics`).
* Tworzy matematyczny model zachowania sieci, który pozwala wykrywać anomalie.

* System trenuje równolegle trzy różne algorytmy, umożliwiając późniejsze porównanie ich skuteczności:
  * *Isolation Forest* – model izoluje anomalie, ponieważ różnią się one od większości danych.
  * *One-Class SVM* – model uczy się granicy obejmującej większość normalnych danych; wszystko poza nią uznawane jest za anomalię.
  * *Metoda progowa* – jeśli wartość cechy wychodzi poza ustalony przedział średnia ± odchylenie standardowe, uznaje się ją za anomalię.

* Dane treningowe mogą być zbierane automatycznie przez wbudowany generator ruchu sieciowego (oparty na bibliotece Selenium), który symuluje zachowanie użytkownika przeglądającego internet.
* Wytrenowane modele są zapisywane do plików w formacie pickle (folder `models/`), a informacje o nich (nazwa, typ algorytmu, data treningu, parametry, flaga aktywności) są rejestrowane w tabeli `model_info` w bazie danych.
* Dzięki temu system umożliwia przełączanie aktywnego modelu wykrywającego anomalie bez konieczności ponownego trenowania.
* Model trenuje się na danych normalnych, a następnie testuje na nowych danych, aby sprawdzić skuteczność.
* Po wytrenowaniu model jest gotowy do analizowania nowych danych w czasie rzeczywistym.
* Narzędzia: Python, Scikit-Learn, Pandas, NumPy, joblib, Selenium.

## **d) Moduł 4 - wykrywanie anomalii:**

* Nowe dane ruchu sieciowego są przetwarzane i porównywane z aktualnie aktywnym modelem (wczytywanym z bazy danych na podstawie flagi `is_active` w tabeli `model_info`).
System oblicza `anomaly_score`, czyli miarę odchylenia od normy.
* Jeśli wynik przekracza ustalony próg, zdarzenie klasyfikuje się jako anomalia.
* Wykryte anomalie są przekazywane do modułu alertów.
* Ten moduł działa w czasie rzeczywistym i stale monitoruje sieć.
* **Narzędzia:** Python i Scikit-Learn.

## **e) Moduł 5 - system alertów:**

* Każda wykryta anomalia jest rejestrowana i przypisywany jest jej poziom istotności (`low`, `medium`, `high`).
Poziom istotności jest wyznaczany na podstawie `anomaly_score` według ustalonych progów:
  * `score < -0.5` → `high`
  * `score < -0.2` → `medium`
  * `score >= -0.2` → `low`

* Alerty są zapisywane w bazie danych (tabela `alerts`) i mogą być wyświetlane administratorowi.
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
* **Narzędzia:** MariaDB i Python (ORM: SQLAlchemy).

## **g) Moduł 7 - panel administratora:**

* Wyświetla `anomaly_score` w czasie rzeczywistym i listę wykrytych alertów.
* Panel pokazuje status sieci (OK lub zagrożenie) i wizualizuje ruch sieciowy w formie wykresów.
* Dostęp do panelu administratora jest chroniony logowaniem, które wymaga podania poprawnych danych użytkownika zapisanych w bazie systemu.
* Umożliwia przegląd historii zdarzeń i raportów.
* Panel administratora zawiera zakładki umożliwiające przeglądanie bieżącego stanu sieci, listy wykrytych alertów, historii anomalii oraz generowania raportów i analizy trendów.
* Pozwala filtrować i sortować alerty według czasu, typu i poziomu istotności.
* Panel umożliwia eksport danych do plików CSV lub PDF.
* **Narzędzia:** Python i Django lub FastAPI i Chart.js do wykresów.

## **Ogólne zabezpieczenia systemu:**

* System stosuje szyfrowane połączenia (HTTPS/SSL) między frontendem a backendem, aby chronić dane przesyłane w sieci.
* Wprowadzenie ograniczenia liczby prób logowania - po kilku nieudanych próbach konto może być tymczasowo zablokowane.
* Wszystkie dane wprowadzane przez użytkownika są walidowane, aby zapobiegać atakom typu SQL Injection lub XSS.
* System może grupować podobne alerty w jedno zdarzenie, ograniczając nadmiar powiadomień i ułatwiając pracę administratora.
* Uprawnienia są ograniczone do administratorów, brak ról dla zwykłych użytkowników, co zmniejsza ryzyko nieautoryzowanego dostępu.
* Panel administratora jest chroniony logowaniem - dostęp mają tylko użytkownicy zarejestrowani w systemie.
* Hasła użytkowników są przechowywane w postaci hash, co uniemożliwia ich odczyt w bazie danych.

## **Dodatkowe uwagi o systemie:**

* Możliwość wizualizacji danych w panelu administratora ułatwia szybkie reagowanie na zagrożenia i przegląd stanu sieci.
* System jest modularny - składa się z części odpowiedzialnej za zbieranie danych, wykrywanie anomalii, generowanie alertów i raportów, co ułatwia rozwój i konserwację.
* System obsługuje dane historyczne, co pozwala analizować trendy w ruchu sieciowym oraz skuteczność wykrywania anomalii.
* System przewiduje możliwość rozszerzenia funkcjonalności - np. dodanie nowych typów alertów, dodatkowych metryk sieciowych lub nowych modeli ML.
* Zastosowanie relacyjnej bazy danych umożliwia spójne przechowywanie danych i logiczne powiązanie rekordów między modułami.

## **Testowanie systemu:**

* System został przetestowany w warunkach kontrolowanych, z wykorzystaniem narzędzia `nmap` do symulacji ataku typu skanowanie portów (SYN scan). Testy potwierdziły skuteczność wszystkich trzech algorytmów w wykrywaniu anomalii:
  * **Isolation Forest** - stabilne wyniki (ok. `-0.73`), szybka i pewna reakcja od pierwszego okna czasowego.
  * **One-Class SVM** - stopniowa eskalacja pewności (od `-0.15` do `-1.23`), bardziej zachowawczy na początku.
  * **Metoda progowa** - najbardziej agresywna reakcja (wyniki nawet do `-10809`), bardzo czuła na nagłe piki pojedynczych metryk.