import time
import random
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

#konfiguracja logowania

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

#lista stron

WEBSITES = [
    "https://www.reddit.com",
    "https://www.pinterest.com",
    "https://www.youtube.com",
    "https://shinden.pl",
    "https://www.webtoons.com",
    "https://lubimyczytac.pl",
    "https://www.wikipedia.org",
    "https://www.khanacademy.org",
    "https://github.com",
    "https://stackoverflow.com",
    "https://developer.mozilla.org",
    "https://www.canva.com",
    "https://www.bbc.com",
    "https://www.onet.pl",
    "https://news.ycombinator.com",
    "https://www.allegro.pl",
]

def generate_traffic(duration_hours=2):
    
    #konfiguracja przeglądarki Chrome

    chrome_options = Options()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    logger.info("Uruchamianie przeglądarki Chrome...")
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=chrome_options
    )
    
    end_time = time.time() + (duration_hours * 3600)
    visits_count = 0
    start_time = time.time()
    
    logger.info(f"Generowanie ruchu rozpoczęte na {duration_hours} godzin(y)...")
    
    try:
        while time.time() < end_time:

            #wybór losowej strony

            url = random.choice(WEBSITES)
            
            try:
                logger.info(f"Odwiedzam: {url}")
                driver.get(url)
                visits_count += 1
                
                #losowy czas czytania strony (między 5 a 30 sekund)

                reading_time = random.uniform(5, 30)
                time.sleep(reading_time)
                
                #kliknięcie (czasami) w losowy link na stronie (30% szans)

                if random.random() < 0.3:
                    try:
                        links = driver.find_elements("tag name", "a")
                        if links:
                            random_link = random.choice(links[:20])
                            href = random_link.get_attribute("href")
                            if href and href.startswith("http"):
                                logger.info(f"  → Klikam link: {href[:80]}")
                                driver.get(href)
                                visits_count += 1
                                time.sleep(random.uniform(3, 15))
                    except Exception:
                        pass  #ignorowanie błędów klikania
                
                #losowa przerwa między stronami (między 2 a 10 sekund)

                pause = random.uniform(2, 10)
                time.sleep(pause)
                
                #wyświetlenie postępu co 10 odwiedzin
                
                if visits_count % 10 == 0:
                    elapsed = (time.time() - start_time) / 60
                    logger.info(f"Postęp: {visits_count} odwiedzin w {elapsed:.1f} minut")
                
            except Exception as e:
                logger.warning(f"Błąd podczas odwiedzania {url}: {e}")
                time.sleep(5)
    
    except KeyboardInterrupt:
        logger.info("Generowanie ruchu zatrzymane przez użytkownika.")
    finally:
        driver.quit()
        elapsed_total = (time.time() - start_time) / 60
        logger.info(f"Generowanie ruchu zakończone. Łącznie odwiedzin: {visits_count} w {elapsed_total:.1f} minut")

if __name__ == "__main__":
    generate_traffic(duration_hours=2) #generowanie ruchu przez 2 godziny