# Projekt bazy danych systemu

Projekt bazy danych został zaprojektowany jako relacyjna baza danych, której zadaniem jest przechowywanie i organizowanie informacji dotyczących ruchu sieciowego, wykrytych anomalii, alertów, modeli uczenia maszynowego, użytkowników, raportów oraz logów systemowych.

## **Tabele**
W projekcie bazy danych systemu przewidziano następujące tabele:

| **Tabela**                                | **Nazwa**       | **Kolumny**                                                                                                        | **Opis**                                                                                                                                                                                   | **Dodatkowe informacje**                                                                                                        |
| ----------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| Metryki ruchu sieciowego                  | network_metrics | {id; timestamp; packets_count; connections_count; unique_ips; unique_ports; avg_packet_size; tcp_ratio; udp_ratio} | Tabela przechowuje zagregowane cechy ruchu sieciowego w określonych przedziałach czasowych. Dane te stanowią wejście dla modelu wykrywania anomalii oraz podstawę do analiz historycznych. | Pole metric_id stanowi klucz obcy do tabeli network_metrics, natomiast model_id wskazuje model, który wykrył anomalię.          |
| Wykryte anomalie                          | anomalies       | {id; timestamp; anomaly_score; severity_level (low/medium/high); description; metric_id; model_id}                 | Tabela zawiera informacje o wykrytych anomaliach, w tym wartość anomaly score oraz poziom istotności.                                                                                      | Pole metric_id stanowi klucz obcy do tabeli network_metrics, natomiast model_id wskazuje model, który wykrył anomalię.          |
| Alerty systemowe                          | alerts          | {id; anomaly_id; created_at; status (new/acknowledged/closed)}                                                     | Tabela przechowuje alerty generowane na podstawie wykrytych anomalii.                                                                                                                      | Pole anomaly_id jest kluczem obcym do tabeli anomalies. Status pozwala śledzić, czy administrator zapoznał się z danym alertem. |
| Użytkownicy systemu                       | users           | {id; username; password_hash; created_at; last_login; is_active}                                                   | Tabela przechowuje dane administratorów systemu.                                                                                                                                           | Hasła są przechowywane w postaci zahashowanej, co zapewnia bezpieczeństwo danych uwierzytelniających.                           |
| Raporty bezpieczeństwa                    | reports         | {id; generated_at; period_start; period_end; generated_by; file_path; summary}                                     | Tabela zawiera informacje o wygenerowanych raportach bezpieczeństwa.                                                                                                                       | Pole generated_by stanowi klucz obcy do tabeli users, wskazując użytkownika, który wygenerował raport.                          |
| Informacje o modelach uczenia maszynowego | model_info      | {id; model_name; algorithm_type; training_date; parameters; accuracy; is_active}                                   | Tabela przechowuje informacje o wytrenowanych modelach wykrywania anomalii, w tym zastosowany algorytm, datę treningu oraz parametry modelu.                                               | Pole is_active pozwala określić, który model jest aktualnie używany w systemie.                                                 |
| Logi techniczne systemu                   | system_logs     | {id; timestamp; log_level (INFO/WARNING/ERROR); message}                                                           | Tabela przechowuje komunikaty techniczne dotyczące działania systemu, co umożliwia diagnostykę błędów oraz monitorowanie stabilności aplikacji.                                            |                                                                                                                                 |

## **Relacje między tabelami**

* network_metrics → anomalies (1:N)

Każdy rekord w network_metrics może mieć wiele powiązanych anomalii (np. jedna godzina ruchu może wygenerować kilka anomalii).

* anomalies → alerts (1:N)

Każda anomalia może generować wiele alertów (np. powtarzające się zdarzenia w tym samym przedziale czasu).

* anomalies → model_info (N:1)

Każda anomalia jest wykrywana przez jeden konkretny model, ale jeden model może wykrywać wiele anomalii.

* users → reports (1:N)

Jeden użytkownik może wygenerować wiele raportów.

* system_logs → tabela niezależna

Logi systemu są niezależne od innych tabel.

## **Klucze główne i obce**

Tabele zaplanowane w bazie danych będą posiadały następujące klucze główne i obce:

**Klucze główne**

* network_metrics (id)
* anomalies (id)
* alerts (id)
* users (id)
* reports (id)
* model_info (id)
* system_logs (id)

**Klucze obce**

* metric_id w anomalies → klucz obcy do network_metrics.id
* model_id w anomalies → klucz obcy do model_info.id
* anomaly_id w alerts → klucz obcy do anomalies.id
* generated_by w reports → klucz obcy do users.id

## **Zabezpieczenia bazy danych**

* Ograniczenie dostępu do bazy tylko dla aplikacji/systemu (kontrola użytkowników bazy)
* Hasła użytkowników w bazie przechowywane w formie hash (bcrypt/sha256)
* Backupy bazy danych w regularnych odstępach czasu
* Użycie transakcji przy zapisach krytycznych danych, aby uniknąć częściowych zapisów
* Weryfikacja integralności danych poprzez klucze główne i obce

## **Dodatkowe uwagi**

* Baza danych jest relacyjna, co zapewnia spójność danych i łatwe powiązanie między metrykami, anomaliami i alertami.
* Dane w tabeli network_metrics są agregowane w przedziałach czasowych, co pozwala modelowi ML mieć stałą liczbę cech i ułatwia analizę trendów.
* Wszystkie istotne relacje między tabelami są chronione kluczami obcymi, co zapobiega zapisaniu nieprawidłowych powiązań między rekordami.
* Baza jest skalowalna – początkowo SQLite do testów i rozwoju, a docelowo PostgreSQL dla większych zbiorów danych i lepszej wydajności.
* Historia danych (metryki, anomalie, alerty) jest archiwizowana, co umożliwia tworzenie raportów i analizowanie trendów w czasie.
* Projekt bazy umożliwia elastyczne generowanie raportów i agregacji danych (np. liczba alertów wysokiego poziomu, średnie anomaly score) dzięki logicznemu podziałowi tabel.
* Struktura bazy jest modularna – łatwo dodać nowe tabele lub rozszerzyć istniejące, np. o nowe typy alertów czy dodatkowe informacje o modelach ML.
* Baza wspiera przechowywanie danych technicznych w system_logs, co ułatwia diagnostykę systemu i utrzymanie stabilności aplikacji.
