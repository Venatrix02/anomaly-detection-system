class SlidingWindow:

#tworzenie okna czasowego o podanej długości w sekundach

    def __init__(self, window_size): 
        self.window_size = window_size
        self.buffer = []

#dodawanie nowych pakietów do okna i usuwanie starych

    def add_packets(self, packets, current_time): 
        self.buffer.extend(packets)
        self.buffer = [
            p for p in self.buffer
            if current_time - p["timestamp"] <= self.window_size
        ]

    def get_packets(self):
        return self.buffer